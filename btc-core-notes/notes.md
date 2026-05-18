# my testing workflow on bitcoin core

the goal here is simple: _you want to review a PR on the bitcoin core repo, understand what it does, and verify it behaves correctly by running the relevant tests locally_. this doc walks you through that based on how i see things...

## 1. clone the repo

you need a local copy of the codebase to build and test anything. you _only get to do this once_.

```bash
git clone https://github.com/bitcoin/bitcoin.git && cd bitcoin
```

## 2. set up PR fetching

by default, git only tracks branches; not pull requests. PRs live under `refs/pull/*/head` on github, and git won't fetch them unless you tell it to.

### Option 1: fetch individual PRs on demand (recommended)

- i usually fetch only the PRs i'm interested in, but you can set up a more general fetch rule if you want to have [all PRs available locally](https://gist.github.com/piscisaureus/3342247) (but beware of the disk space and clutter this can cause).

  ```sh
  # let us do it for a single PR:

  # by the way, it does not usually matter which branch you are on when you run the first two commands as long as you are on a different branch, but i usually start from master/main just to be safe
  git checkout master

  # A. initial - on first attempt when you want to check out a PR for the first time
  git fetch upstream pull/<pr_number>/head:pr-<pr_number>
  git checkout pr-<pr_number>

  # B. later updates - used when you wanna pull in the new changes made by the PR author
  git checkout master
  git fetch upstream +pull/<pr_number>/head:pr-<pr_number> # "+" = overwrite a non-fastforward branch
  git checkout pr-<pr_number>
  ```

an example workflow for the method above (e.g. #12345):

- the first time you check out the PR, you run the first two commands to create a local branch `pr-12345` that tracks the PR.

  ```sh
  # by the way, it does not usually matter which branch you are on when you run the first two commands as long as you are on a different branch, but i usually start from master/main just to be safe
  git checkout master

  git fetch upstream pull/12345/head:pr-12345
  git checkout pr-12345
  ```

- then, when the PR author pushes new commits to the same PR, you can pull those changes into your local `pr-12345` branch by running the last three commands:

  ```sh
  git checkout master
  git fetch upstream +pull/12345/head:pr-12345
  git checkout pr-12345
  ```

### Another Option: add their fork as a remote (if you review them often)

- go to your fork's local repo and add their fork as a remote (you only need to do this once per fork):

  ```sh
  # we are gonna assume the PR author is "alice" and their fork is at github.com/alice/project.git
  git remote add alice git@github.com:alice/project.git # add their fork

  git fetch alice
  git checkout alice/feature-branch
  ```

## 3. compile what you need

bitcoin core is a large codebase. compiling everything takes a long time and most of it you won't need for reviewing a single PR. so we only build the two binaries that matter for running a node and interacting with it: `bitcoind` (the daemon) and `bitcoin-cli` (the RPC client).

the flags below disable everything else; GUI, benchmarks, fuzzing, tests, extra tools; to keep the build fast (_personally i like using a debug build for testing, but you can also do a release build if you want to test the optimized code_):

```bash
cmake -B build \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_CXX_FLAGS_DEBUG="-O0 -ggdb3" \
    -DBUILD_GUI=OFF \
    -DBUILD_BENCH=OFF  \
    -DBUILD_FOR_FUZZING=OFF \
    -DBUILD_KERNEL_LIB=OFF \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_TESTS=OFF \
    -DBUILD_TX=OFF \
    -DBUILD_UTIL=OFF \
    -DBUILD_WALLET_TOOL=OFF && cmake --build build -j 18 --target bitcoind bitcoin-cli
```

> [!TIP]
> the bitcoin repo has a [productivity guide](https://github.com/bitcoin/bitcoin/blob/master/doc/productivity.md#general) with tricks to speed up incremental builds (e.g. using `ccache`).

## 4. run the functional tests

functional tests simulate real node behavior end-to-end. they spin up one or more `bitcoind` instances, run scripted scenarios against them, and check the outcomes. this is the most direct way to verify a PR does what it claims.

from the root of the repo (`bitcoin/`):

```bash
cd ./build/test/functional

# run a specific test file directly
./<test_file_name>.py <...options...>

# run via the test harness (recommended)
# --loglevel=debug gives you verbose output
# --nocleanup keeps the temp dirs so you can inspect logs after the run
# --failfast stops at the first failure, which is usually what you want when testing a PR
./test_runner.py ./feature_init.py --loglevel=debug --nocleanup --failfast
```

## 5. contribute and PROFIT!!

once you understand the PR:

- think about edge cases the existing tests don't cover and write a test for one
- if the approach seems suboptimal, propose an alternative; even a rough sketch is valuable feedback, a patch diff is even better

# in case your feature branch is off from master (ALWAYS just `rebase` it)

- if you have a feature branch that is based on an older master, you can rebase it onto the latest master to get the new changes and make sure your branch is up to date. this is especially important if the PR has been open for a while and there have been many changes to master since then. Almost always **you need a rebase** to get the latest changes from master, and you should do it before you push your branch for review. Here's how you can do it:

  ```sh
  git checkout my-feat
  git fetch upstream
  git rebase upstream/master
  git push --force-with-lease
  ```

# keep up with upstream (ALWAYS just merge it)

- if you have a local master branch that tracks the upstream master, you can merge the latest changes from upstream into your local master and then push it to your fork. This is a common workflow to keep your local master up to date with the upstream master. Here's how you can do it:
  ```sh
  git checkout master
  git fetch upstream
  git merge upstream/master
  git push origin master
  ```

# Locally generate a bitcoin core coverage yourself (just like Marco Falke)

- Build Bitcoin Core with coverage enabled to see exactly which lines are hit by the current test suite:
  - Install `lcov`. On Debian-based systems, you can do this with:
    ```sh
    sudo apt update && sudo apt install lcov
    ```
  - Use the provided script to build Bitcoin Core with coverage flags and run the tests; copy the script to the root of the bitcoin core's local repo and run it:
    ```sh
    bash ./build-coverage.sh
    ```
  - Review the generated HTML report at (provided you're at the project's root): `./coverage_report/index.html`.

# about what the PR's body should look like

The body of the pull request should contain sufficient description of _what_ the patch does, and even more importantly, _why_, with justification and reasoning. You should include references to any discussions (for example, other issues or mailing list discussions).

## references

- [functional tests docs](https://github.com/bitcoin/bitcoin/blob/master/test/functional/README.md)
- [integration tests overview](https://github.com/bitcoin/bitcoin/blob/master/test/README.md)
- [compile and run tests by Jon Atack](https://jonatack.github.io/articles/how-to-compile-bitcoin-core-and-run-the-tests)
- [helping out with reviews](https://jonatack.github.io/articles/on-reviewing-and-helping-those-who-do-it)
- [how to carry out reviews](https://jonatack.github.io/articles/how-to-review-pull-requests-in-bitcoin-core)
