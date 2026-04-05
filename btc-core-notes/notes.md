# testing workflow on bitcoin core

the goal here is simple: _you want to review a PR on the bitcoin core repo, understand what it does, and verify it behaves correctly by running the relevant tests locally_. this doc walks you through that based on how i see things...

## 1. clone the repo

you need a local copy of the codebase to build and test anything. you only do this once.

```bash
git clone https://github.com/bitcoin/bitcoin.git && cd bitcoin
```

## 2. set up PR fetching (one-time)

by default, git only tracks branches; not pull requests. PRs live under `refs/pull/*/head` on github, and git won't fetch them unless you tell it to.

open `.git/config`, find the `[remote "origin"]` section, and add the extra `fetch` line:

```git
[remote "origin"]
url = https://github.com/user/repo.git
fetch = +refs/heads/*:refs/remotes/origin/*

# this line teaches git to also fetch all PRs as local refs under origin/pr/<number>
fetch = +refs/pull/*/head:refs/remotes/origin/pr/*
```

then fetch once to pull down all the PR refs:

```bash
git fetch origin
```

from now on, checking out any PR is just:

```bash
git checkout pr/<PR_number>
```

## 3. compile what you need

bitcoin core is a large codebase. compiling everything takes a long time and most of it you won't need for reviewing a single PR. so we only build the two binaries that matter for running a node and interacting with it: `bitcoind` (the daemon) and `bitcoin-cli` (the RPC client).

the flags below disable everything else; GUI, benchmarks, fuzzing, tests, extra tools; to keep the build fast:

```bash
cmake -B build \
    -DBUILD_GUI=OFF \
    -DBUILD_BENCH=OFF \
    -DBUILD_FOR_FUZZING=OFF \
    -DBUILD_KERNEL_LIB=OFF \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_TESTS=OFF \
    -DBUILD_TX=OFF \
    -DBUILD_UTIL=OFF \
    -DBUILD_WALLET_TOOL=OFF && cmake --build build -j 4 --target bitcoind bitcoin-cli
```

> tip: the bitcoin repo has a [productivity guide](https://github.com/bitcoin/bitcoin/blob/master/doc/productivity.md#general) with tricks to speed up incremental builds (e.g. using `ccache`).

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
./test_runner.py ./feature_init.py --loglevel=debug --nocleanup
```

refs:

- [functional tests docs](https://github.com/bitcoin/bitcoin/blob/master/test/functional/README.md)
- [integration tests overview](https://github.com/bitcoin/bitcoin/blob/master/test/README.md)

## 5. contribute and PROFIT!!

once you understand the PR:

- think about edge cases the existing tests don't cover and write a test for one
- if the approach seems suboptimal, propose an alternative; even a rough sketch is valuable feedback, a patch diff is even better
