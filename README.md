# JWKS Server - Project 2

## Student Information
Name: Abdul Abubakar  
EUID: aoa0169

## Overview
This project extends the basic JWKS server from Project 1 by adding SQLite-backed storage for RSA private keys. Instead of storing keys only in memory, the server now persists keys in a SQLite database file so that keys remain available across restarts.

The server also protects against SQL injection by using parameterized SQL queries for all database operations.

## Database File
The SQLite database file used by this project is:

`totally_not_my_privateKeys.db`

## Table Schema
```sql
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
