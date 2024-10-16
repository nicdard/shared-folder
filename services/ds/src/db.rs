// Copyright (C) 2024 Nicola Dardanis <nicdard@gmail.com>
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, version 3.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.
//
use std::error::Error;

use rocket_db_pools::{sqlx, Connection, Database};
use sqlx::{mysql::MySqlQueryResult, Acquire, Execute};

/// The database connection pool.
// https://api.rocket.rs/v0.5/rocket_db_pools/
#[derive(Database)]
#[database("ds")]
pub struct DbConn(pub sqlx::MySqlPool);

#[derive(sqlx::FromRow, Clone, Debug)]
pub struct UserEntity {
    pub user_email: String,
}

#[derive(sqlx::FromRow, Debug, Clone)]
pub struct FolderEntity {
    /// The id of the folder, auto-generated by the DB.
    pub folder_id: u64,
}

#[derive(sqlx::FromRow, Debug, Clone)]
pub struct PendingGroupMessageEntity {
    /// The id of the message, autogenerated by the DB. We can use it to order the messages when delivering to the clients.
    pub message_id: u64,
    pub folder_id: u64,
    pub user_email: String,
    pub payload: Vec<u8>,
    /// The creator of this pending message, for ACL purposes.
    pub creator: String,
}

#[derive(sqlx::FromRow, Debug, Clone)]
pub struct GroupMessageEntity {
    /// The id of the message, autogenerated by the DB. We can use it to order the messages when delivering to the clients.
    pub message_id: u64,
    pub folder_id: u64,
    pub user_email: String,
    pub payload: Vec<u8>,
    pub application_payload: Vec<u8>,
}

#[derive(sqlx::FromRow, Debug, Clone)]
pub struct KeyPackageEntity {
    pub key_package_id: u64,
    pub user_email: String,
    pub key_package: Vec<u8>,
}

/// The type of a DB connection (as a request guard).
pub type DbConnection = Connection<DbConn>;

/// The number of parameters in MySQL must fit in a `u16`.
const BIND_LIMIT: usize = 65535;

/// Remove the entry from folders_relation for the given folder and user.
pub async fn remove_user_from_folder(
    folder_id: u64,
    email: &str,
    mut db: Connection<DbConn>,
) -> Result<(), sqlx::Error> {
    let mut transaction = db.begin().await?;
    log::debug!(
        "Start to remove user `{}` from folder `{}`",
        email,
        folder_id
    );
    let _ = sqlx::query("DELETE FROM folders_users WHERE folder_id = ? AND user_email = ?")
        .bind(folder_id)
        .bind(email)
        .execute(&mut *transaction)
        .await?;
    log::debug!(
        "Removed user `{}` from folder `{}` completed.",
        email,
        folder_id
    );
    // Cleanup the proposals and pending messages for the user in this folder.
    let _ = delete_all_messages_by_user_and_folder(email, folder_id, &mut transaction).await?;
    let count = count_users_for_folder(folder_id, &mut transaction).await?;
    log::debug!("Users count for folder `{}`: `{}`", folder_id, count);
    if count == 0 {
        // remove also the folder if no users have access to it anymore
        let _ = sqlx::query("DELETE FROM folders WHERE folder_id = ?")
            .bind(folder_id)
            .execute(&mut *transaction)
            .await?;
        log::debug!("Removed folder `{}`", folder_id);
    }
    log::debug!(
        "Remove user `{}` from folder `{}` completed.",
        email,
        folder_id
    );
    transaction.commit().await?;
    Ok(())
}

/// Get the user by the email from the database.
pub async fn get_user_by_email(
    email: &str,
    mut db: Connection<DbConn>,
) -> Result<UserEntity, sqlx::Error> {
    sqlx::query_as::<_, UserEntity>("SELECT * FROM users WHERE user_email = ? LIMIT 1")
        .bind(&email)
        .fetch_one(&mut **db)
        .await
}

/// Insert the user in the database.
pub async fn insert_user(email: &str, mut db: Connection<DbConn>) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO users (user_email) VALUES (?)")
        .bind(&email)
        .execute(&mut **db)
        .await
        .map(|_| ())
}

/// List all the users from the database.
pub async fn list_users(mut db: Connection<DbConn>) -> Result<Vec<UserEntity>, sqlx::Error> {
    sqlx::query_as::<_, UserEntity>("SELECT * FROM users")
        .fetch_all(&mut **db)
        .await
}

/// Get the folder by the id from the database.
pub async fn get_folder_by_id(
    email: &str,
    folder_id: u64,
    mut db: Connection<DbConn>,
) -> Result<FolderEntity, sqlx::Error> {
    sqlx::query_as::<_, FolderEntity>(
        "
    SELECT * FROM folders 
    JOIN folders_users ON folders.folder_id = folders_users.folder_id 
    WHERE folders.folder_id = ? AND folders_users.user_email = ?",
    )
    .bind(&folder_id)
    .bind(&email)
    .fetch_one(&mut **db)
    .await
}

/// List all the folders for a user from the database.
pub async fn list_folders(
    email: &str,
    mut db: Connection<DbConn>,
) -> Result<Vec<FolderEntity>, sqlx::Error> {
    sqlx::query_as::<_, FolderEntity>(
        "SELECT * FROM folders 
        JOIN folders_users ON folders.folder_id = folders_users.folder_id 
        JOIN users ON users.user_email = folders_users.user_email 
        WHERE users.user_email = ?",
    )
    .bind(&email)
    .fetch_all(&mut **db)
    .await
}

/// List all the folders for a user from the database.
async fn list_folders_for_user(
    email: &str,
    db: &mut sqlx::Transaction<'_, sqlx::MySql>,
) -> Result<Vec<FolderEntity>, sqlx::Error> {
    sqlx::query_as::<_, FolderEntity>(
        "SELECT * 
        FROM folders 
            JOIN folders_users ON folders.folder_id = folders_users.folder_id 
            JOIN users ON users.user_email = folders_users.user_email 
        WHERE users.user_email = ?",
    )
    .bind(&email)
    .fetch_all(&mut **db)
    .await
}

/// Count the number of users that have access to the folder.
async fn count_users_for_folder(
    folder_id: u64,
    transaction: &mut sqlx::Transaction<'_, sqlx::MySql>,
) -> Result<i64, sqlx::Error> {
    let count: Option<i64> =
        sqlx::query_scalar("SELECT COUNT(*) FROM folders_users WHERE folder_id = ?")
            .bind(folder_id)
            .fetch_optional(&mut **transaction)
            .await?;
    if let Some(count) = count {
        Ok(count)
    } else {
        Err(sqlx::Error::RowNotFound)
    }
}

pub async fn list_users_for_folder(
    user_emails: Vec<&str>,
    folder_id: u64,
    db: &mut Connection<DbConn>,
) -> Result<Vec<UserEntity>, sqlx::Error> {
    let mut transaction = db.begin().await?;
    let result =
        list_users_for_folder_transaction(&user_emails, folder_id, &mut transaction).await?;
    transaction.commit().await?;
    Ok(result)
}

/// Returns the users that have access to the folder filtering by the given emails.
pub async fn list_users_for_folder_transaction(
    user_emails: &Vec<&str>,
    folder_id: u64,
    transaction: &mut sqlx::Transaction<'_, sqlx::MySql>,
) -> Result<Vec<UserEntity>, sqlx::Error> {
    let chunks = user_emails.chunks(BIND_LIMIT);
    let mut users = Vec::with_capacity(user_emails.capacity());
    for chunk in chunks {
        let users_chunks = unsafe_list_users_for_folder(chunk, folder_id, transaction).await?;
        users.extend(users_chunks);
    }
    Ok(users)
}

/// List all the folders for given users from the database.
/// Note: You should limit the number of values to the maximum supported value in MySQL!
/// Use [`list_users_for_folder`](list_users_for_folder) instead
async fn unsafe_list_users_for_folder(
    emails: &[&str],
    folder_id: u64,
    transaction: &mut sqlx::Transaction<'_, sqlx::MySql>,
) -> Result<Vec<UserEntity>, sqlx::Error> {
    let mut query_builder = sqlx::QueryBuilder::new(
        "SELECT * 
        FROM folders 
            JOIN folders_users ON folders.folder_id = folders_users.folder_id 
            JOIN users ON users.user_email = folders_users.user_email 
        WHERE 
            folders.folder_id = ",
    );
    query_builder.push_bind(folder_id);
    query_builder.push(" AND users.user_email IN ");
    query_builder.push_tuples(emails, |mut b, user_email| {
        b.push_bind(user_email);
    });
    let query = query_builder.build_query_as::<UserEntity>();
    log::debug!("Query: `{}`", query.sql());
    query.fetch_all(&mut **transaction).await
}

/// Create a folder and attach it to the creator user.
pub async fn insert_folder_and_relation(
    user_email: &str,
    mut db: Connection<DbConn>,
) -> Result<u64, Box<dyn Error + Send + Sync>> {
    log::debug!("Start to create a folder for user: `{}`", user_email);
    let mut transaction = db.begin().await?;
    let folder_id = insert_folder(&mut transaction).await?.last_insert_id();
    log::debug!("Inserted folder with id: `{}`", folder_id);
    insert_folders_to_users(folder_id, &vec![user_email], &mut transaction).await?;
    log::debug!("Inserted folder to users completed.");
    transaction.commit().await?;
    Ok(folder_id)
}

/// Insert relations between folder and users.
/// This is used to implement sharing of a folder.
pub async fn insert_folder_users_relations(
    folder_id: u64,
    owner_email: &String,
    user_emails: Vec<&str>,
    proposal: Option<&[u8]>,
    mut db: Connection<DbConn>,
) -> Result<(Vec<String>, Option<Vec<u64>>), sqlx::Error> {
    let mut transaction = db.begin().await?;
    log::debug!(
        "Start inserting relations for folder id: `{}` and users `{:?}`",
        folder_id,
        user_emails
    );
    let is_owner: Vec<String> =
        list_users_for_folder_transaction(&user_emails, folder_id, &mut transaction)
            .await?
            .iter()
            .map(|user| user.user_email.clone())
            .collect();
    log::debug!("Existing owners: `{:?}`", is_owner);
    if is_owner.is_empty() || !is_owner.contains(&owner_email) {
        log::debug!(
            "Db conflict: folder with id `{}` does not exist for user `{}`.",
            folder_id,
            owner_email
        );
        return Err(sqlx::Error::RowNotFound.into());
    }
    let to_add: Vec<&str> = user_emails
        .into_iter()
        .filter(|user| !is_owner.contains(&user.to_string()))
        .map(AsRef::as_ref)
        .collect();
    let _ = insert_folders_to_users(folder_id, &to_add, &mut transaction).await?;
    let mut message_ids = vec![];
    if let Some(payload) = proposal {
        // insert the pending message before the new user is part of this folder. This proposal is to add the user itself, so it will be unreadable to him.
        let insert_message_result =
            insert_message_transaction(&owner_email, folder_id, payload, &mut transaction).await;
        if let Err(e) = insert_message_result {
            if let Err(e) = e {
                return Err(e);
            } else {
                return Ok((vec![], None));
            }
        }
        message_ids = insert_message_result.unwrap().1;
    }
    log::debug!("Inserted folder to users completed.");
    transaction.commit().await?;
    // The transaction is ended implicitely when the `transaction` object is dropped.
    Ok((is_owner, Some(message_ids)))
}

/// Safely get all [`UserEntity`] by their emails.
/// If the array of users is to big, the query will be chunked.
pub async fn get_users_by_emails(
    user_emails: &Vec<&str>,
    db: &mut Connection<DbConn>,
) -> Result<Vec<UserEntity>, sqlx::Error> {
    let mut transaction = db.begin().await?;
    let chunks = user_emails.chunks(BIND_LIMIT);
    let mut users = Vec::with_capacity(user_emails.capacity());
    log::debug!("Start to query the db to retrieve users");
    for chunk in chunks {
        let result = unsafe_get_users_by_emails(chunk, &mut transaction).await;
        if let Ok(to_add) = result {
            users.extend(to_add);
        } else {
            log::debug!("Error while retrieving users `{:?}`", result);
            return result;
        }
    }
    log::debug!("Retrieved users: {:?}", users);
    transaction.commit().await?;
    Ok(users)
}

/// Get the list of user ids given the emails
/// Note: You should limit the number of values to the maximum supported value in MySQL!
/// Use [`get_users_by_emails`] instead
async fn unsafe_get_users_by_emails(
    user_emails: &[&str],
    transaction: &mut sqlx::Transaction<'_, sqlx::MySql>,
) -> Result<Vec<UserEntity>, sqlx::Error> {
    let mut query_builder = sqlx::QueryBuilder::new("SELECT * FROM users WHERE (user_email) IN");
    query_builder.push_tuples(user_emails, |mut b, user_email| {
        b.push_bind(user_email);
    });
    let query = query_builder.build_query_as::<UserEntity>();
    query.fetch_all(&mut **transaction).await
}

/// Insert the folder in the database.
async fn insert_folder(
    transaction: &mut sqlx::Transaction<'_, sqlx::MySql>,
) -> Result<MySqlQueryResult, sqlx::Error> {
    log::debug!("Creating a new folder");
    sqlx::query("INSERT INTO folders () VALUES ()")
        .execute(&mut **transaction)
        .await
}

/// Insert a row inside the relations `folder_users` table for each of the user_id.
async fn insert_folders_to_users(
    folder_id: u64,
    user_emails: &Vec<&str>,
    transaction: &mut sqlx::Transaction<'_, sqlx::MySql>,
) -> Result<(), sqlx::Error> {
    let chunks = user_emails.chunks(BIND_LIMIT);
    for chunk in chunks {
        let result = unsafe_insert_folders_to_users(folder_id, chunk, transaction).await;
        if result.is_err() {
            return result;
        }
    }
    Ok(())
}

/// Insert multiple relationship between folder and users.
/// Note: You should limit the number of values to the maximum supported value in MySQL!
/// Use [`insert_folders_to_users`](insert_folders_to_users) instead
async fn unsafe_insert_folders_to_users(
    folder_id: u64,
    user_emails: &[&str],
    transaction: &mut sqlx::Transaction<'_, sqlx::MySql>,
) -> Result<(), sqlx::Error> {
    let values = user_emails.iter().map(|user_email| (folder_id, user_email));
    let mut query_builder =
        sqlx::QueryBuilder::new("INSERT INTO folders_users(folder_id, user_email)");
    let query = query_builder
        .push_values(values, |mut b, (folder_id, user_email)| {
            b.push_bind(folder_id).push_bind(user_email);
        })
        .build();
    query.execute(&mut **transaction).await.map(|_| ())
}

/// Delete the user from the database.
async fn delete_user(email: &str, mut db: Connection<DbConn>) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM users WHERE user_email = ?")
        .bind(&email)
        .execute(&mut **db)
        .await
        .map(|_| ())
}

/// Returns all users that partecipate in a folder.
async fn list_users_by_folder(
    folder_id: u64,
    transaction: &mut sqlx::Transaction<'_, sqlx::MySql>,
) -> Result<Vec<String>, sqlx::Error> {
    log::debug!("Listing users for folder `{}`", folder_id);
    let query =
        sqlx::query_scalar::<_, String>("SELECT user_email FROM folders_users WHERE folder_id = ?")
            .bind(&folder_id);
    query.fetch_all(&mut **transaction).await
}

pub async fn insert_welcome(
    sender_email: &str,
    receiver_email: &str,
    folder_id: u64,
    payload: &[u8],
    db: &mut Connection<DbConn>,
) -> Result<(), sqlx::Error> {
    let mut transaction = db.begin().await?;
    let users = list_users_by_folder(folder_id, &mut transaction).await?;
    if !users.contains(&sender_email.to_string()) || !users.contains(&receiver_email.to_string()) {
        return Err(sqlx::Error::RowNotFound);
    }
    log::debug!("Inserting a welcome message for user `{}`", receiver_email);
    sqlx::query("INSERT INTO welcome_messages(user_email, folder_id, payload) VALUES (?, ?, ?)")
        .bind(receiver_email)
        .bind(folder_id)
        .bind(payload)
        .execute(&mut *transaction)
        .await?;
    let _ = transaction.commit().await;
    Ok(())
}

/// Removes a message from the db. To be done only when the client acks that the message was processed.
pub async fn delete_welcome(
    message_id: u64,
    user_email: &str,
    folder_id: u64,
    mut db: Connection<DbConn>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM welcome_messages WHERE message_id = ? AND user_email = ? AND folder_id = ?",
    )
    .bind(message_id)
    .bind(user_email)
    .bind(folder_id)
    .execute(&mut **db)
    .await
    .map(|_| ())
}

async fn insert_message_transaction(
    sender_email: &str,
    folder_id: u64,
    payload: &[u8],
    transaction: &mut sqlx::Transaction<'_, sqlx::MySql>,
) -> Result<(Vec<String>, Vec<u64>), Result<i64, sqlx::Error>> {
    let pending_messages =
        count_pending_messages_for_folder_and_user(folder_id, sender_email, transaction).await;
    let mut message_ids = vec![];
    match pending_messages {
        Ok(pending_msgs) => {
            if pending_msgs == 0 {
                match list_users_by_folder(folder_id, transaction).await {
                    Ok(users) => {
                        log::debug!(
                            "Found users to write pending messages to: {}",
                            users.join(",")
                        );
                        for user in users.clone() {
                            // We replicate the payload in the db, as we do not want to check each time we get an ack of reception from a client
                            // that the message was processed.
                            if user != sender_email {
                                log::debug!(
                                    "Inserting a pending group message for user `{}`",
                                    user
                                );
                                let res = sqlx::query(
                                    "INSERT INTO pending_group_messages(user_email, folder_id, payload, creator) VALUES (?, ?, ?, ?)",
                                )
                                .bind(user)
                                .bind(folder_id)
                                .bind(payload)
                                .bind(sender_email)
                                .execute(&mut **transaction)
                                .await;
                                if let Err(e) = res {
                                    return Err(Err(e));
                                }
                                message_ids.push(res.unwrap().last_insert_id());
                            }
                        }
                        Ok((users, message_ids))
                    }
                    Err(e) => Err(Err(e)),
                }
            } else {
                Err(Ok(pending_msgs))
            }
        }
        Err(e) => Err(Err(e)),
    }
}

/// Insert a message for a group in the queue of all other members apart from the sender.
/// Returns an error and abort transaction if the sender has still pending messages in that folder.
pub async fn insert_message(
    sender_email: &str,
    folder_id: u64,
    payload: &[u8],
    db: &mut Connection<DbConn>,
) -> Result<(Vec<String>, Vec<u64>), Result<i64, sqlx::Error>> {
    match db.begin().await {
        Ok(mut transaction) => {
            let users_and_msg_ids =
                insert_message_transaction(sender_email, folder_id, payload, &mut transaction)
                    .await;
            let res = transaction.commit().await;
            if let Err(e) = res {
                return Err(Err(e));
            }
            users_and_msg_ids
        }
        Err(e) => Err(Err(e)),
    }
}

/// Count the number of users that have access to the folder.
async fn count_pending_messages_for_folder_and_user(
    folder_id: u64,
    user_email: &str,
    transaction: &mut sqlx::Transaction<'_, sqlx::MySql>,
) -> Result<i64, sqlx::Error> {
    log::debug!(
        "Counting the number of pending messages for the user `{}`",
        user_email
    );
    let count: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pending_group_messages WHERE user_email = ? AND folder_id = ?",
    )
    .bind(user_email)
    .bind(folder_id)
    .fetch_optional(&mut **transaction)
    .await?;
    if let Some(count) = count {
        Ok(count)
    } else {
        log::error!("This should not happen!");
        Err(sqlx::Error::RowNotFound)
    }
}

/// Removes a message from the db. To be done only when the client acks that the message was processed.
pub async fn delete_message(
    message_id: u64,
    user_email: &str,
    folder_id: u64,
    mut db: Connection<DbConn>,
) -> Result<bool, sqlx::Error> {
    let mut transaction = db.begin().await?;
    let first = sqlx::query_as::<_, PendingGroupMessageEntity>(
        "SELECT * FROM pending_group_messages WHERE user_email = ? AND folder_id = ? ORDER BY message_id ASC LIMIT 1",
    )
    .bind(user_email)
    .bind(folder_id)
    .fetch_one(&mut *transaction)
    .await?;
    let result = if first.message_id < message_id {
        Ok(false)
    } else {
        sqlx::query("DELETE FROM pending_group_messages WHERE message_id = ? AND user_email = ? AND folder_id = ?")
            .bind(message_id)
            .bind(user_email)
            .bind(folder_id)
            .execute(&mut *transaction)
            .await
            .map(|_| true)
    };
    transaction.commit().await?;
    result
}

/// Removes a message from the db. To be done only when the client acks that the message was processed.
pub async fn delete_all_messages_by_user_and_folder(
    user_email: &str,
    folder_id: u64,
    transaction: &mut sqlx::Transaction<'_, sqlx::MySql>,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM pending_group_messages WHERE user_email = ? AND folder_id = ?")
        .bind(user_email)
        .bind(folder_id)
        .execute(&mut **transaction)
        .await
        .map(|_| ())
}

/// Returns all pending messages of a user for a given folder. (uses the index internally).
pub async fn list_pending_messages_by_folder_and_user(
    folder_id: u64,
    user_email: &str,
    transaction: &mut sqlx::Transaction<'_, sqlx::MySql>,
) -> Result<Vec<PendingGroupMessageEntity>, sqlx::Error> {
    sqlx::query_as::<_, PendingGroupMessageEntity>(
        "SELECT * FROM pending_group_messages WHERE user_email = ? AND folder_id = ?",
    )
    .bind(user_email)
    .bind(folder_id)
    .fetch_all(&mut **transaction)
    .await
}

/// Returns all pending messages of a user for a given folder. (uses the index internally).
pub async fn get_first_message_by_folder_and_user(
    folder_id: u64,
    user_email: &str,
    mut db: Connection<DbConn>,
) -> Result<Option<GroupMessageEntity>, sqlx::Error> {
    let mut transaction = db.begin().await?;
    let pending = sqlx::query_as::<_, PendingGroupMessageEntity>(
        "SELECT * FROM pending_group_messages WHERE user_email = ? AND folder_id = ? ORDER BY message_id ASC LIMIT 1",
    )
    .bind(user_email)
    .bind(folder_id)
    .fetch_one(&mut *transaction)
    .await?;
    let application_msg_payload =
        sqlx::query_scalar("SELECT payload FROM application_messages WHERE message_id = ?")
            .bind(pending.message_id)
            .fetch_one(&mut *transaction)
            .await;
    if let Err(sqlx::Error::RowNotFound) = application_msg_payload {
        // This is not an error, it means that the message is not yet processable.
        return Ok(None);
    }
    if let Err(e) = application_msg_payload {
        return Err(e);
    }
    transaction.commit().await?;
    Ok(Some(GroupMessageEntity {
        message_id: pending.message_id,
        folder_id: pending.folder_id,
        user_email: pending.user_email,
        payload: pending.payload,
        application_payload: application_msg_payload.unwrap(),
    }))
}

/// Returns all pending messages of a user for a given folder. (uses the index internally).
pub async fn get_welcome_message_by_folder_and_user(
    folder_id: u64,
    user_email: &str,
    mut db: Connection<DbConn>,
) -> Result<PendingGroupMessageEntity, sqlx::Error> {
    sqlx::query_as::<_, PendingGroupMessageEntity>(
        "SELECT * FROM welcome_messages WHERE user_email = ? AND folder_id = ?",
    )
    .bind(user_email)
    .bind(folder_id)
    .fetch_one(&mut **db)
    .await
}

pub async fn insert_key_package(
    user_email: &str,
    key_package: Vec<u8>,
    mut db: Connection<DbConn>,
) -> Result<u64, sqlx::Error> {
    sqlx::query("INSERT INTO key_packages(user_email, key_package) VALUES (?, ?)")
        .bind(user_email)
        .bind(key_package)
        .execute(&mut **db)
        .await
        .map(|r| r.last_insert_id())
}

pub async fn consume_key_package(
    user_email: &str,
    requestor: &str,
    folder_id: u64,
    mut db: Connection<DbConn>,
) -> Result<KeyPackageEntity, sqlx::Error> {
    let mut transaction = db.begin().await?;
    log::debug!("Starting to retrieve the key package for {user_email} requested by {requestor}");
    let user_emails = vec![requestor, &user_email];
    let users_for_folder =
        list_users_for_folder_transaction(&user_emails, folder_id, &mut transaction).await;
    if let Err(e) = users_for_folder {
        return Err(e);
    }
    let key_package_entity = sqlx::query_as::<_, KeyPackageEntity>(
        "SELECT * FROM key_packages WHERE user_email = (?) ORDER BY key_package_id ASC LIMIT 1",
    )
    .bind(&user_email)
    .fetch_one(&mut *transaction)
    .await?;
    log::debug!(
        "Found key package with id {} for {user_email}",
        key_package_entity.key_package_id
    );
    sqlx::query("DELETE FROM key_packages WHERE key_package_id = ?")
        .bind(key_package_entity.key_package_id)
        .execute(&mut *transaction)
        .await?;
    log::debug!(
        "Key package {} was deleted.",
        key_package_entity.key_package_id
    );
    transaction.commit().await?;
    Ok(key_package_entity)
}

pub async fn insert_application_message<'r>(
    message_ids: &Vec<u64>,
    sender_email: &str,
    folder_id: u64,
    payload: &'r [u8],
    mut db: Connection<DbConn>,
) -> Result<Vec<String>, sqlx::Error> {
    let mut transaction = db.begin().await?;
    // Retrieve all pending message ids.
    let mut query_builder = sqlx::QueryBuilder::new(
        "SELECT * FROM pending_group_messages WHERE pending_group_messages.folder_id = ",
    );
    query_builder.push_bind(folder_id);
    query_builder.push(" AND pending_group_messages.user_email = ");
    query_builder.push_bind(sender_email);
    query_builder.push(" AND pending_group_messages.message_id IN ");
    query_builder.push_tuples(message_ids, |mut b, message_id| {
        b.push_bind(message_id);
    });
    let query = query_builder.build_query_as::<PendingGroupMessageEntity>();
    log::debug!("Query: `{}`", query.sql());
    let pending_messages = query.fetch_all(&mut *transaction).await?;
    // Let's patch all the pending messages we found.
    let values = message_ids.iter().map(|message_id| (message_id, payload));
    let mut query_builder =
        sqlx::QueryBuilder::new("INSERT INTO application_messages(message_id, payload)");
    let query = query_builder
        .push_values(values, |mut b, (message_id, payload)| {
            b.push_bind(message_id).push_bind(payload);
        })
        .build();
    query.execute(&mut *transaction).await?;
    let users_with_changes = pending_messages
        .iter()
        .map(|pending_message| pending_message.user_email.clone())
        .collect();
    transaction.commit().await?;
    Ok(users_with_changes)
}
