#ifndef VERSION_H
#define VERSION_H

/* 是否为正式版 */
#define IS_RELEASE_VERSION      ( 1 )

/* 图标 */
#define APP_NAME                "CetCryptoToolkit"
#define PRODUCT_ICON            "favorite.ico"

/* 版本号定义 */
#define VER_MAJOR               2       /* 主版本号 */
#define VER_MINOR               0       /* 次版本号 */
#define VER_MICRO               2       /* 小版本号 */

/* 正式版发布日期 
 * (CXYQK5152.CCTK100.EB17) 的含义：
    CXYQK5152: CetXiyuan QT Kernel 5.15.2
    CCTK100: CetCryptoToolkit 100
    EB17: E(24年, A-20年)B(11月 A-10月 B-11月 C-12月)17(06日 17-11(月)=06)
*/
#define RELEASE_DATE            "(3.0.18)(CXYQK5152.CCTK100.FC29)" // "(2025-12-17)"

/* 补丁包号(月+日+序号) */
#define PATCH_PACKET            "2051"

/* 版本宏定义 */
#define VERSION_CHECK(major, minor, micro)  (((major)<<16)|((minor)<<8)|((micro)<<0))
#define VERSION_STRING(major, minor, micro) __STR(major) "." __STR(minor) "." __STR(micro)
#define DIRECT_STRING(major, minor, micro) __STR(major) __STR(minor) __STR(micro)
#define __STR(var)   #var

#if (IS_RELEASE_VERSION > 0)
#define TIP_VERSION             RELEASE_DATE
#define APP_VERSION             VERSION_STRING(VER_MAJOR, VER_MINOR, VER_MICRO)
#else
#define TIP_VERSION             RELEASE_DATE " Patch-" PATCH_PACKET
#define APP_VERSION             VERSION_STRING(VER_MAJOR, VER_MINOR, VER_MICRO) "." PATCH_PACKET
#endif

#define COMPANY_NAME            "CetXiyuan"

/* 文件版本 */
#define FILE_VERSION            VER_MAJOR,VER_MINOR,VER_MICRO
#define FILE_VERSION_STR        APP_VERSION

/* 产品版本 */
#define PRODUCT_VERSION         FILE_VERSION
#define PRODUCT_VERSION_STR     FILE_VERSION_STR

/* 文件描述 */
#define FILE_DESCRIPTION        APP_NAME " based on Qt 5.15.2 (MinGW, 32 bit)"

/* 版权 */
#define LEGAL_COPYRIGHT         "Copyright 2008-2035 The " COMPANY_NAME " Ltd. All rights reserved."

/* 原始应用名 */
#define ORIGINAL_NAME           APP_NAME ".exe"

/* 产品名称 */
#define PRODUCT_NAME            APP_NAME DIRECT_STRING(VER_MAJOR, VER_MINOR, 0)

/* 域名 */
#define ORGANIZATION_DOMAIN     "https://www.cetxiyuan.com/"

#endif // VERSION_H
