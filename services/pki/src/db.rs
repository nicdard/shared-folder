use rocket_db_pools::{sqlx, Connection, Database};

/// The database connection pool.
// https://api.rocket.rs/v0.5/rocket_db_pools/
#[derive(Database)]
#[database("pki")]
pub struct DbConn(pub sqlx::MySqlPool);

/// The certificate entity stored in the `certificates` table.
#[derive(sqlx::FromRow)]
pub struct CertificateEntity {
    pub id: i64,
    pub email: String,
    pub certificate: String,
}

pub type DbConnection = Connection<DbConn>;

/// Get the certificate by the email from the database.
pub async fn get_certificate_by_email(
    email: &str,
    mut db: Connection<DbConn>,
) -> Result<CertificateEntity, sqlx::Error> {
    sqlx::query_as::<_, CertificateEntity>("SELECT * FROM certificates WHERE email = ?")
        .bind(&email)
        .fetch_one(&mut **db)
        .await
}

/// Insert the certificate in the database.
/// If the email is already present, return an error.
/// The email field in the database has a unique constraint.
pub async fn insert_certificate(
    email: &str,
    certificate: &str,
    mut db: Connection<DbConn>,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO certificates (email, certificate) VALUES (?, ?)")
        .bind(&email)
        .bind(&certificate)
        .execute(&mut **db)
        .await
        .map(|_| ())
}