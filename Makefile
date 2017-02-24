VERSION = 0.0.1

all:
	mkdir -p _build
	rm -rf _build/*
	cp -a src/* _build
	cd _build && phpize && ./configure && make

install:
	cd _build && make install

deb:
	rm -rf binprot-$(VERSION)
	mkdir binprot-$(VERSION)
	cp -a src/* binprot-$(VERSION)
	cd .. && \
		tar --exclude-vcs \
			-Jcvf php-binprot_$(VERSION).orig.tar.xz \
			php-bin_prot && \
		cd -
	debuild -uc -us

deb-precise:
	rm -rf binprot-$(VERSION)
	mkdir -p binprot-$(VERSION)/php-bin_prot
	cp src/* binprot-$(VERSION)/php-bin_prot
	cp -a debian binprot-$(VERSION)/php-bin_prot
	cp debian/precise/* binprot-$(VERSION)/php-bin_prot/debian
	cd binprot-$(VERSION) && \
		tar --exclude-vcs \
			-Jcvf php5-binprot_$(VERSION).orig.tar.xz \
			php-bin_prot && \
		cd -
	cd binprot-$(VERSION)/php-bin_prot && debuild -uc -us
	mv binprot-$(VERSION)/php5-* ..

clean:
	rm -rf _build
	rm -rf build-*
	rm -rf binprot-*
	dh_clean
