PORTNAME=	pfSense-pkg-PfManager
PORTVERSION=	0.1.0
CATEGORIES=	sysutils
MASTER_SITES=	# empty
DISTFILES=	# empty
EXTRACT_ONLY=	# empty

MAINTAINER=	https://github.com/riccanet/ComSense/issues
COMMENT=	PfManager management and monitoring agent for pfSense
WWW=		https://github.com/riccanet/PfManager

LICENSE=	APACHE20

NO_BUILD=	yes
NO_MTREE=	yes
NO_ARCH=	yes

SUB_FILES=	pkg-install pkg-deinstall
SUB_LIST=	PORTNAME=${PORTNAME}

do-extract:
	${MKDIR} ${WRKSRC}

do-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/pkg/pfmanager/lib
	${MKDIR} ${STAGEDIR}${PREFIX}/sbin
	${MKDIR} ${STAGEDIR}${PREFIX}/www
	${MKDIR} ${STAGEDIR}/etc/inc/priv
	${MKDIR} ${STAGEDIR}${DATADIR}
	${INSTALL_DATA} -m 0644 ${FILESDIR}${PREFIX}/pkg/pfmanager.xml \
		${STAGEDIR}${PREFIX}/pkg
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/pfmanager.inc \
		${STAGEDIR}${PREFIX}/pkg
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/pfmanager/agent.php \
		${STAGEDIR}${PREFIX}/pkg/pfmanager
.for f in agent client collect common policies tasks
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/pfmanager/lib/${f}.inc \
		${STAGEDIR}${PREFIX}/pkg/pfmanager/lib
.endfor
	${INSTALL_SCRIPT} ${FILESDIR}${PREFIX}/sbin/pfmanager-agentd \
		${STAGEDIR}${PREFIX}/sbin
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/pfmanager_status.php \
		${STAGEDIR}${PREFIX}/www
	${INSTALL_DATA} ${FILESDIR}/etc/inc/priv/pfmanager.priv.inc \
		${STAGEDIR}/etc/inc/priv
	${INSTALL_DATA} ${FILESDIR}${DATADIR}/info.xml \
		${STAGEDIR}${DATADIR}
	@${REINPLACE_CMD} -i '' -e "s|%%PKGVERSION%%|${PKGVERSION}|" \
		${STAGEDIR}${DATADIR}/info.xml \
		${STAGEDIR}${PREFIX}/pkg/pfmanager.xml

.include <bsd.port.mk>
