APPNAME := porecry
APPSRC := ./cmd/$(APPNAME)

PKG := github.com/sebidude/$(APPNAME)
TEST_PKG_LIST := kube crypto

GITCOMMITHASH := $(shell git log --max-count=1 --pretty="format:%h" HEAD)
GITCOMMIT := -X main.gitcommit=$(GITCOMMITHASH)

VERSIONTAG := $(shell git describe --tags --abbrev=0)
VERSION := -X main.appversion=$(VERSIONTAG)

BUILDTIMEVALUE := $(shell date +%Y-%m-%dT%H:%M:%S%z)
BUILDTIME := -X main.buildtime=$(BUILDTIMEVALUE)

LDFLAGS := '-extldflags "-static" -d -s -w $(GITCOMMIT) $(VERSION) $(BUILDTIME)'
LDFLAGS_WINDOWS := '-extldflags "-static" -s -w $(GITCOMMIT) $(VERSION) $(BUILDTIME)'

KUBEAPIVERSION := 1.15

clean: 
	rm -rf build

info: 
	@echo - appname:   $(APPNAME)
	@echo - version:   $(VERSIONTAG)
	@echo - commit:    $(GITCOMMITHASH)
	@echo - buildtime: $(BUILDTIMEVALUE) 

dep:
	@go get -v -d ./...

install: build-linux
	cp build/linux/$(APPNAME) $$GOPATH/bin/
	
build-linux: info dep
	@echo Building for linux
	@mkdir -p build/linux
	@CGO_ENABLED=0 \
	GOOS=linux \
	go build -o build/linux/$(APPNAME)-$(VERSIONTAG)-$(GITCOMMITHASH) -a -ldflags $(LDFLAGS) $(APPSRC)
	@cp build/linux/$(APPNAME)-$(VERSIONTAG)-$(GITCOMMITHASH) build/linux/$(APPNAME)

image:
	docker build -t sebidude/$(APPNAME):$(VERSIONTAG) .

publish:
	docker push sebidude/$(APPNAME):$(VERSIONTAG) 

unittests:
	CGO_ENABLED=0 go test -v -count=1 -cover -coverprofile cover.out -p 1 $(addprefix $(PKG)/, $(TEST_PKG_LIST))

test: 
	@echo Running tests
	@rm -f secret.yaml
	@build/linux/$(APPNAME) init --local -s helmcrypt -n local -o secret.yaml
	@echo -n "Encrypt values: "	
	@build/linux/$(APPNAME) post --in unsafe.test.yaml --out safe.yaml
	@grep tralalla safe.yaml >/dev/null
	@if grep testme safe.yaml >/dev/null; then exit 1; fi
	@echo "ok"
	@echo -n "Decrypt values: "
	@build/linux/$(APPNAME) post --in safe.yaml -p | grep testme >/dev/null
	@echo "ok"
	@echo -n "Encrypt and decrypt text: "
	@echo 123 | build/linux/$(APPNAME) enc --local -s secret.yaml | build/linux/$(APPNAME) dec --local -s secret.yaml | grep 123 >/dev/null
	@echo "ok"
	@rm -f secret.yaml

clean-tests:
	rm safe.yaml mysecret.yaml safemap.yaml

pack: build-linux
	@cd build/linux && tar cvfz $(APPNAME)-$(VERSIONTAG).tar.gz $(APPNAME)
