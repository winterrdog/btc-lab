# testing workflow on bitcoin core

## clone repo (_this is a one-time thing_)

```bash
git clone https://github.com/bitcoin/bitcoin.git && cd bitcoin
```

## check out to the PR of interest:

if you've not yet setup your github config to fetch Github PRs locally, do this:

- open your `.git/config` file and find the `[remote "origin"]` section (_this is a one-time thing_). It usually looks like this:

  ```git
  [remote "origin"]
  url = https://github.com/user/repo.git
  fetch = +refs/heads/_:refs/remotes/origin/_

  # ADD THIS LINE BELOW: >>
  fetch = +refs/pull/*/head:refs/remotes/origin/pr/*
  # << ADD THIS LINE ABOVE
  ```

- save the file and run `git fetch origin` to fetch all the new refs (_this is a one-time thing_)

- now, whenever you want to test a PR, you just type:
  ```bash
  git checkout pr/<PR_number>
  ```

## compile wat u need

e.g. here we only compile
the Bitcoin daemon and cli (but if you wanna compile
everything, just run `make` or `cmake --build build`):

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

refer to [productivity notes](https://github.com/bitcoin/bitcoin/blob/master/doc/productivity.md#general) on bitcoin repo in order to speed up compilations

## run the tests (_functional_, in this case)

assuming you're in the root of the repo i.e.
`bitcoin/`
and assuming you compiled bitcoin:

```bash
cd ./build/test/functional

# run a specific test file (e.g. feature_init.py)
./<test_file_name>.py <...test_file_options...>

# using the harness (recommended). here we run with debug output and prevent cleanup of temp dirs so that we can look/analyse the logs
./test_runner.py ./feature_init.py --loglevel=debug --nocleanup
```

refs:

- [functional tests docs](https://github.com/bitcoin/bitcoin/blob/master/test/functional/README.md)
- [integration tests](https://github.com/bitcoin/bitcoin/blob/master/test/README.md)

## now contribute and PROFIT!

- think of a test case that could be added to the PR
- propose a better algorithm even 😃
