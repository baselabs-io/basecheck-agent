package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

func main() {
	path := flag.String("path", "examples/siem-demo/demo.sqlite", "SQLite fixture path")
	flag.Parse()

	if err := os.Remove(*path); err != nil && !os.IsNotExist(err) {
		panic(err)
	}

	db, err := sql.Open("sqlite", *path)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	statements := []string{
		"PRAGMA foreign_keys = OFF",
		"PRAGMA journal_mode = OFF",
		"CREATE TABLE parent (id INTEGER PRIMARY KEY)",
		"CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id))",
		"INSERT INTO child (id, parent_id) VALUES (1, 999)",
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			panic(err)
		}
	}

	fmt.Printf("Created intentionally unsafe SQLite fixture: %s\n", *path)
}
