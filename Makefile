.PHONY: all test clean

build:
	@echo "Building..."
	docker build -t bc-docker .

run1:
	@echo "Running terminal one..."
	docker run -p 4444:4444/tcp -p 8000:8000/tcp -it bc-docker

run2:
	@echo "Running terminal two..."
	docker run -p 4445:4445/tcp -p 8001:8001/tcp -it bc-docker

