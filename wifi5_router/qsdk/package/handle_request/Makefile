include $(TOPDIR)/rules.mk

# Define the package name and version
PKG_NAME:=handle_request
PKG_VERSION:=1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_DEPENDS:=libjson-c

define Package/handle_request
    SECTION:=utils
    CATEGORY:=Utilities
    TITLE:=Handle Request CGI
    DEPENDS:=$(PKG_DEPENDS)
endef

define Build/Compile
    echo "Compiling CGI"
	$(MAKE) -C $(PKG_BUILD_DIR) \
        CC="$(TARGET_CC)" CFLAGS="$(TARGET_CFLAGS)" \
        LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/handle_request/install
    echo "Installing CGI"
	$(INSTALL_DIR) $(1)/www/cgi-bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/handle_request $(1)/www/cgi-bin/handle_request.cgi
endef

# Define the source directory for your build
SOURCE_DIR=$(TOPDIR)/package/handle_request/src

define Build/Configure
	mkdir -p $(PKG_BUILD_DIR)
	cp -r $(SOURCE_DIR)/* $(PKG_BUILD_DIR)/
endef

$(eval $(call BuildPackage,handle_request))


