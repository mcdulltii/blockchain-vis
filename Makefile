.PHONY: all test clean

build:
	@echo "Building...\n"
	docker-compose build && docker-compose up -d
	@echo "\nDone!"

run1:
	@echo "Running terminal one...\n"
	docker exec -it blockchain-vis_run1_1 bash
	@echo "\nDone!"

run2:
	@echo "Running terminal two...\n"
	docker exec -it blockchain-vis_run2_1 bash
	@echo "\nDone!"

down:
	@echo "Shutting down docker images...\n"
	docker-compose down -v
	@echo "\nDone!"

local:
	@echo "Building executable...\n"
	go get -v -d ./...
	go build
	chmod +x ./bl*
	@echo "\nDone!"
