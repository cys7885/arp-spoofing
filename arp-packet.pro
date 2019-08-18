TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -pthread
SOURCES += main.c \
    arp_relay.c \
    arp_request.c \
    get_rsc.c

HEADERS += \
    utils.h
