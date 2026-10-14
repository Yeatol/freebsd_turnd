PROG_CXX=	turnd
SRCS=		main.cpp network.cpp turn.cpp
MAN=

CXXSTD=		c++23
LDADD+=		-pthread

PREFIX?=	/usr/local
BINDIR?=	${PREFIX}/sbin

MK_DEBUG_FILES=	no
WITH_RC_SUBR?=	yes

.if ${WITH_RC_SUBR} == "yes"
FILES=			turnd.sh
FILESNAME_turnd.sh=	turnd
FILESDIR=		${PREFIX}/etc/rc.d
FILESMODE=		0555

CLEANFILES+=	turnd.sh

turnd.sh: turnd.in
	sed -e 's|%%PREFIX%%|${PREFIX}|g' ${.ALLSRC} > ${.TARGET}
.endif

.include <bsd.prog.mk>
