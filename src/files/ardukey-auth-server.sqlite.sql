CREATE TABLE API
(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    secret TEXT(64) NOT NULL,
    modified DATE,
    created DATE,
    enabled INTEGER(1) NOT NULL DEFAULT 1
);

CREATE TRIGGER INSERT_API AFTER INSERT ON API BEGIN
    UPDATE API SET modified = DATETIME('now', 'localtime'), created = DATETIME('now', 'localtime')
    WHERE rowid = new.rowid;
END;

CREATE TRIGGER UPDATE_API BEFORE UPDATE ON API BEGIN
    UPDATE API SET modified = DATETIME('now', 'localtime')
    WHERE rowid = new.rowid;
END;

CREATE TABLE ARDUKEY
(
    publicid TEXT(12) PRIMARY KEY,
    secretid TEXT(12) NOT NULL,
    counter INTEGER(5) NOT NULL DEFAULT 0,
    sessioncounter INTEGER(3) NOT NULL DEFAULT 0,
    timestamp INTEGER(8) DEFAULT 0,
    aeskey TEXT(32) NOT NULL,
    modified DATE,
    created DATE,
    enabled INTEGER(1) NOT NULL DEFAULT 1
);

CREATE TRIGGER INSERT_ARDUKEY AFTER INSERT ON ARDUKEY BEGIN
    UPDATE ARDUKEY SET modified = DATETIME('now', 'localtime'), created = DATETIME('now', 'localtime')
    WHERE rowid = new.rowid;
END;

CREATE TRIGGER UPDATE_ARDUKEY BEFORE UPDATE ON ARDUKEY BEGIN
    UPDATE ARDUKEY SET modified = DATETIME('now', 'localtime')
    WHERE rowid = new.rowid;
END;

CREATE TABLE QUEUED
(
    hash TEXT(64) PRIMARY KEY,
    created DATE
);

CREATE TRIGGER INSERT_QUEUED AFTER INSERT ON QUEUED BEGIN
    UPDATE QUEUED SET created = DATETIME('now', 'localtime')
    WHERE rowid = new.rowid;
END;
