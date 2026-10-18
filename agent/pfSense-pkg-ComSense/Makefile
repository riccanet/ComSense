PORTNAME=	pfSense-pkg-ComSense
PORTVERSION=	0.1.0
CATEGORIES=	sysutils
MASTER_SITES=	# empty
DISTFILES=	# empty
EXTRACT_ONLY=	# empty

MAINTAINER=	https://github.com/riccanet/ComSense/issues
COMMENT=	ComSense Firewall Manager agent for pfSense
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
	${MKDIR} ${STAGEDIR}${PREFIX}/pkg/comsense/lib
	${MKDIR} ${STAGEDIR}${PREFIX}/sbin
	${MKDIR} ${STAGEDIR}${PREFIX}/www
	${MKDIR} ${STAGEDIR}/etc/inc/priv
	${MKDIR} ${STAGEDIR}${DATADIR}
	${INSTALL_DATA} -m 0644 ${FILESDIR}${PREFIX}/pkg/comsense.xml \
		${STAGEDIR}${PREFIX}/pkg
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/comsense.inc \
		${STAGEDIR}${PREFIX}/pkg
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/comsense/agent.php \
		${STAGEDIR}${PREFIX}/pkg/comsense
.for f in agent client collect common policies tasks
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/comsense/lib/${f}.inc \
		${STAGEDIR}${PREFIX}/pkg/comsense/lib
.endfor
	${INSTALL_SCRIPT} ${FILESDIR}${PREFIX}/sbin/comsense-agentd \
		${STAGEDIR}${PREFIX}/sbin
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/comsense_status.php \
		${STAGEDIR}${PREFIX}/www
	${INSTALL_DATA} ${FILESDIR}/etc/inc/priv/comsense.priv.inc \
		${STAGEDIR}/etc/inc/priv
	${INSTALL_DATA} ${FILESDIR}${DATADIR}/info.xml \
		${STAGEDIR}${DATADIR}
	@${REINPLACE_CMD} -i '' -e "s|%%PKGVERSION%%|${PKGVERSION}|" \
		${STAGEDIR}${DATADIR}/info.xml \
		${STAGEDIR}${PREFIX}/pkg/comsense.xml

.include <bsd.port.mk>
