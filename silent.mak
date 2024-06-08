# Silent build or verbose
AM_DEFAULT_VERBOSITY = 0

am__v_color_cc=\033[27;32m
am__v_color_ld=\033[27;34m
am__v_color_rc=\033[27;36m
am__v_color_off=\033[m

ifeq ($(ECHO_E),)
ifeq ($(shell /bin/echo -e),-e)
ECHO_E=/bin/echo
else
ECHO_E=/bin/echo -e
endif
endif

# AM_V_CC and AM_V_AR are invoked from templates,
# and must therefore double-quote make variables

am__v_CC_0     = @$(ECHO_E) "  $(am__v_color_cc)CC$(am__v_color_off)      " $$@;
am__v_AS_0     = @$(ECHO_E) "  $(am__v_color_cc)AS$(am__v_color_off)      " $@;
am__v_CPPAS_0  = @$(ECHO_E) "  $(am__v_color_cc)CPPAS$(am__v_color_off)   " $@;
am__v_CXX_0    = @$(ECHO_E) "  $(am__v_color_cc)CXX$(am__v_color_off)     " $$@;
am__v_OBJC_0   = @$(ECHO_E) "  $(am__v_color_cc)OBJC$(am__v_color_off)    " $@;
am__v_CCLD_0   = @$(ECHO_E) "  $(am__v_color_ld)CCLD$(am__v_color_off)    " $@;
am__v_AR_0     = @$(ECHO_E) "  $(am__v_color_ld)AR$(am__v_color_off)      " $$@;
am__v_CXXLD_0  = @$(ECHO_E) "  $(am__v_color_ld)CXXLD$(am__v_color_off)   " $@;
am__v_OBJCLD_0 = @$(ECHO_E) "  $(am__v_color_ld)OBJCLD$(am__v_color_off)  " $@;

am__v_CC_1     = 
am__v_CC_      = $(am__v_CC_$(AM_DEFAULT_VERBOSITY))
AM_V_CC        = $(am__v_CC_$(V))

am__v_AS_1     = 
am__v_AS_      = $(am__v_AS_$(AM_DEFAULT_VERBOSITY))
AM_V_AS        = $(am__v_AS_$(V))

am__v_CPPAS_1  = 
am__v_CPPAS_   = $(am__v_CPPAS_$(AM_DEFAULT_VERBOSITY))
AM_V_CPPAS     = $(am__v_CPPAS_$(V))

am__v_CXX_1    = 
am__v_CXX_     = $(am__v_CXX_$(AM_DEFAULT_VERBOSITY))
AM_V_CXX       = $(am__v_CXX_$(V))

am__v_OBJC_1   = 
am__v_OBJC_    = $(am__v_OBJC_$(AM_DEFAULT_VERBOSITY))
AM_V_OBJC      = $(am__v_OBJC_$(V))

am__v_CCLD_1   = 
am__v_CCLD_    = $(am__v_CCLD_$(AM_DEFAULT_VERBOSITY))
AM_V_CCLD      = $(am__v_CCLD_$(V))

am__v_AR_1     = 
am__v_AR_      = $(am__v_AR_$(AM_DEFAULT_VERBOSITY))
AM_V_AR        = $(am__v_AR_$(V))

am__v_CXXLD_1  = 
am__v_CXXLD_   = $(am__v_CXXLD_$(AM_DEFAULT_VERBOSITY))
AM_V_CXXLD     = $(am__v_CXXLD_$(V))

am__v_OBJCLD_1 = 
am__v_OBJCLD_  = $(am__v_OBJCLD_$(AM_DEFAULT_VERBOSITY))
AM_V_OBJCLD    = $(am__v_OBJCLD_$(V))


am__v_GEN_0    = @echo "  GEN     " $@;
am__v_GEN_1    = @echo generating $@;
am__v_GEN_     = $(am__v_GEN_$(AM_DEFAULT_VERBOSITY))
AM_V_GEN       = $(am__v_GEN_$(V))

am__v_MSGFMT_0 = @echo "  MSGFMT  "
am__v_MSGFMT_1 = @echo generating
am__v_MSGFMT_  = $(am__v_MSGFMT_$(AM_DEFAULT_VERBOSITY))
AM_V_MSGFMT    = $(am__v_MSGFMT_$(V))

am__v_MAN_0    = @echo "  MAN   "
am__v_MAN_1    = @echo formatting
am__v_MAN_     = $(am__v_MAN_$(AM_DEFAULT_VERBOSITY))
AM_V_MAN       = $(am__v_MAN_$(V))

am__v_at_0     = @
am__v_at_1     =
am__v_at_      = $(am__v_at_$(AM_DEFAULT_VERBOSITY))
AM_V_at        = $(am__v_at_$(V))

am__v_RC_0     = @$(ECHO_E) "  $(am__v_color_rc)RC$(am__v_color_off)      " $@;
am__v_RC_1     = 
am__v_RC_      = $(am__v_RC_$(AM_DEFAULT_VERBOSITY))
AM_V_RC        = $(am__v_RC_$(V))
