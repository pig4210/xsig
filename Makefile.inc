################################################################
INCLUDE_PATH = $(SRCPATH)/include
CFLAGS      += /I"$(INCLUDE_PATH)"

CFLAGS      += /Zc:threadSafeInit-

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

all : $(ProjectName).dll $(ProjectName).exe
	@echo make done.