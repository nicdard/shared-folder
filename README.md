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

### LaTex

You can install a complete version of LaTex from [the latex project](https://www.latex-project.org/get/).

### VSCode

Please, install the extensions suggested by the editor:
* [Latex-workshop](https://github.com/James-Yu/LaTeX-Workshop/wiki/Install)
* You should add the binary for LaTex in your `PATH` environment variable, if you downloaded LaTex following the above in MacOs you should add the following line in your `~/.zshrc`:
```bash
export PATH=$PATH:/Library/TeX/texbin
```
