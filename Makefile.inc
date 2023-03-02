################################################################
INCLUDE_PATH    := $(SRCPATH)/include
CFLAGS          += /I"$(INCLUDE_PATH)"

CFLAGS          += /Zc:threadSafeInit-

XLIB_HS         := $(wildcard D:/xlib/*.h)
XLIB_HSS        := $(patsubst D:/xlib/%,$(INCLUDE_PATH)/xlib/%,$(XLIB_HS))

.PHONY : check_xlib
check_xlib : $(XLIB_HSS)

$(INCLUDE_PATH)/xlib/%.h : D:/xlib/%.h
	@echo $^ ~~ $@
	@cd $(INCLUDE_PATH)/xlib && copy "D:\xlib\$(^F)" "$(@F)" >nul
	@if exist x86 rd /s /q x86
	@if exist x64 rd /s /q x64

vpath xit.cc   $(INCLUDE_PATH)/xit
################################################################
xit.o                    : $(INCLUDE_PATH)/xit/xit.h
xsig_dll.o               :
xsig_exe.o               :
################################################################
$(ProjectName).dll : xsig_dll.o | $(DSTPATH)
	$(LINK) $(LDFLAGS) /DLL $(LDFLAGS_WINDOWS) /OUT:"$(DSTPATH)/$(@F)" $(^F)
	@echo.

$(ProjectName).exe : xit.o xsig_exe.o | $(DSTPATH)
	$(LINK) $(LDFLAGS) $(LDFLAGS_CONSOLE) /OUT:"$(DSTPATH)/$(@F)" $(^F)

all : check_xlib $(ProjectName).dll $(ProjectName).exe
	@echo make done.