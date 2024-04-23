# Shared Folder Implementation

The folder is organised in the following way:
* `proposal/`: contains LaTex files of the initial proposal of this project
* `style-reference.md`: contains a list of useful LaTex tips and styling guides

## Git submodules
The project relies on the [cryptobib](https://cryptobib.di.ens.fr/manual) submodule.
After cloning or pulling the repository, please run:

```bash
git submodule update --init
```

To update the cryptobib submodule:
```bash
cd cryptobib && git pull origin master
```

## Updating the submodules

The first time you clone the project please execute:
```bash
git submodule init
```

Then, every time you udpate from main, you should update cryptobib if `git status` finds differences for that folder:
```bash
git submodule update
```

## Development process

Please, open a PR with your changes and ask for review.
To do so, please create a new branch where to store your changes first (assuming you are in main):
* Stash any changes you have locally (optional)

```bash
git add . && git stash
```

* Update your main local branch

```bash
git pull --rebase origin main
```

* Switch to a new branch:

```bash
git checkout -b "your-branch-name"
```

* Unstash your changes (optional, conflicts might arise, in which case you need to solve them, you can check the offending files using `git status`):

```bash
git stash pop
```

* Commit your changes to the branch and push

```bash
git add . && git commit -m "your message" && git push
```

* Follow the link displayed in the terminal to open a PR against main.

## Local development / Editor setup

### External dependencies

Mocked external dependencies are available and can be activeted using the provided [docker-compose.yaml](services/docker-compose.yaml)
The project uses [LocalStack](services/aws) to simulate AWS S3.

To start the dependencies locally:
```bash
docker compose -f services/docker-compose.yaml up 
```
To stop them:
```bash
docker compose -f services/docker-compose.yaml down --remove-orphans
```

### LaTex

You can install a complete version of LaTex from [the latex project](https://www.latex-project.org/get/).

### VSCode

Please, install the extensions suggested by the editor:
* [Latex-workshop](https://github.com/James-Yu/LaTeX-Workshop/wiki/Install)
* You should add the binary for LaTex in your `PATH` environment variable, if you downloaded LaTex following the above in MacOs you should add the following line in your `~/.zshrc`:
```bash
export PATH=$PATH:/Library/TeX/texbin
```

## License

License is automatically applied using `licensure`. You can install it using:
```bash
cargo install licensure
```
and run using:
```bash
licensure --project
```

## Code structure

* `www`: contains the website, loading the ssf implementation compiled to webassebly. (probably not in scope)
* `ssf`: the actual core protocol of the Secure Shared Folder scheme.
* `cli`: the Command Line Interface for the Secure Shared Folder scheme.
* `baseline`: the naive implementation of the Shared Folder system to compare the SSF against (for performance testing).
* `services`: dockerized dependencies to be used while developing. It contains databases, cloud services and so on. Further it contains the code for the backends:
    * `pki`: our Public Key Infrastructure service, basically a local Certificate Authority server
    * `ds`: our SSF server (called DS from Delivery Service - although we might change name if we use a pre-built delivery service), providing the required infrastructure to store and retrieve the files from the Cloud Storage Provider, and performing ACL checks on the folder access.


## High level Architecture:

As S3 storage is not publicly available, we organise the system in 3 main different components:
* CA server (PKI), to address security concerns for this we could also use `KeyTransparency` but it is out of scope for the thesis. The server is also providing a `verify` endpoint, but clients can just use perform the verification by themselves using the public CA certificate (this would implement the `Authorization Service` verify in our case).
* Client application, each client creates a key pair for asymmetric encryption, and `register` to the CA 
  * we want to re-use this as a form of authentication as well, instead of having a password, so we would like to use mTLS.
* the SSF server, which is basically the company providing the storage. In our case, we offload the storage in S3. All the endpoints of the SSF are authenticated using mTLS. The SSF server is further divided into different logical components:
  * DS: delivery service
  * Storage service (manages the folders and ACLs to them)

