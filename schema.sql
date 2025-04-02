DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,  /* Will store encrypted username */
    password TEXT NOT NULL,         /* Will store hashed password */
    email TEXT NOT NULL,            /* Will store encrypted email */
    mobile TEXT NOT NULL,           /* Will store encrypted mobile */
    address TEXT NOT NULL,          /* Will store encrypted address */
    profile_image TEXT,             /* Column to store image path */
    security_answer_1 TEXT NOT NULL,   /* Answer to first security question */
    security_answer_2 TEXT NOT NULL,   /* Answer to second security question */
    is_being_edited INTEGER DEFAULT 0, /* Indicates if the record is being edited */
    edited_by TEXT DEFAULT NULL        /* Stores the username of the editor */
);