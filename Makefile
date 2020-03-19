.PHONY: all test clean

build:
	@echo "Building..."
	docker-compose build && docker-compose up -d

run1:
	@echo "Running terminal one..."
	docker exec -it blockchain-vis_run1_1 bash

run2:
	@echo "Running terminal two..."
	docker exec -it blockchain-vis_run2_1 bash

test:
	go test -v -timeout=5m -race ./...
