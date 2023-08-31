
```
apt install libnl-3-dev libnl-genl-3-dev libevent-dev
```

```
apt install cmake libssl-dev
PICOTLS_COMMIT=9a3a311b2db4ebfa91ca365a954177541f02c5b3
git clone https://github.com/h2o/picotls
cd picotls
git checkout $PICOTLS_COMMIT
git submodule init
git submodule update
cmake .
make
make picotls-openssl
cd ..
```
