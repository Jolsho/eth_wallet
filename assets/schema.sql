CREATE TABLE IF NOT EXISTS users (
    uid       TEXT PRIMARY KEY CHECK(length(uid) = 16),
    username  TEXT NOT NULL UNIQUE,
    salt      BLOB NOT NULL CHECK(length(salt) = 16),
    m_salt    BLOB NOT NULL CHECK(length(m_salt) = 16),
    mn_nonce  BLOB NOT NULL CHECK(length(mn_nonce) = 12),
    mnemonic  BLOB NOT NULL,
    hashword  BLOB NOT NULL CHECK(length(hashword) = 32),
    sz_count  INT NOT NULL DEFAULT 0,
    eth_count INT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sz_keys (
    uid  TEXT NOT NULL,
    addr BLOB NOT NULL CHECK(length(addr) = 20),
    nonce BLOB NOT NULL,
    prk  BLOB NOT NULL CHECK(length(prk) = 48),
    FOREIGN KEY (uid) REFERENCES users(uid) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS eth_keys (
    uid  TEXT NOT NULL,
    addr BLOB NOT NULL CHECK(length(addr) = 20),
    nonce BLOB NOT NULL,
    prk  BLOB NOT NULL CHECK(length(prk) = 48),
    FOREIGN KEY (uid) REFERENCES users(uid) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sym_keys (
    uid  TEXT NOT NULL,
    id   BLOB NOT NULL CHECK(length(id) = 32),
    nonce BLOB NOT NULL,
    prk  BLOB NOT NULL CHECK(length(prk) = 48),
    FOREIGN KEY (uid) REFERENCES users(uid) ON DELETE CASCADE
);
