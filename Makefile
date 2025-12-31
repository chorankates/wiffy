.PHONY: build run clean deps install

build:
	go build -o wiffy .

run: build
	./wiffy

clean:
	rm -f wiffy wiffy.db wiffy.db-journal wiffy.db-wal wiffy.db-shm

deps:
	go mod download
	go mod tidy

install:
	go install .

dev:
	go run main.go

