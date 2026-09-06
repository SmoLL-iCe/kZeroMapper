#pragma once

/**
 * ==============================================================================
 * kZeroMapper - Configuração Global de Provedores / Backends
 * ------------------------------------------------------------------------------
 * Comente ou descomente as macros abaixo para incluir ou excluir provedores
 * da compilação da biblioteca kZeroMapper.
 *
 * Se uma macro for comentada ou desativada, todo o código do backend e o
 * driver vulnerável embutido correspondente (.sys) serão completamente
 * excluídos da compilação da lib, reduzindo o tamanho do binário e a superfície de ataque.
 *
 * Se o chamador solicitar um provedor desativado, MapDriver retornará o erro
 * StatusCode::KM_ProviderNotSupported (0x9181).
 * ==============================================================================
 */

#ifndef KZEROMAPPER_CUSTOM_CONFIG

// Habilite ou desabilite os provedores que desejar compilar na lib:
#define KZEROMAPPER_ENABLE_CPUZ
#define KZEROMAPPER_ENABLE_DIRECTIO64
#define KZEROMAPPER_ENABLE_KDMAPPER
#define KZEROMAPPER_ENABLE_KKYUM
#define KZEROMAPPER_ENABLE_RTCORE64
#define KZEROMAPPER_ENABLE_VIRTUALBOX

#endif

// Suporte a macros alternativas ou passadas por flag de compilação (/D)
#if defined(ENABLE_CPUZ) && !defined(KZEROMAPPER_ENABLE_CPUZ)
#define KZEROMAPPER_ENABLE_CPUZ
#endif

#if defined(ENABLE_DIRECTIO64) && !defined(KZEROMAPPER_ENABLE_DIRECTIO64)
#define KZEROMAPPER_ENABLE_DIRECTIO64
#endif

#if defined(ENABLE_KDMAPPER) && !defined(KZEROMAPPER_ENABLE_KDMAPPER)
#define KZEROMAPPER_ENABLE_KDMAPPER
#endif

#if defined(ENABLE_KKYUM) && !defined(KZEROMAPPER_ENABLE_KKYUM)
#define KZEROMAPPER_ENABLE_KKYUM
#endif

#if defined(ENABLE_RTCORE64) && !defined(KZEROMAPPER_ENABLE_RTCORE64)
#define KZEROMAPPER_ENABLE_RTCORE64
#endif

#if defined(ENABLE_VIRTUALBOX) && !defined(KZEROMAPPER_ENABLE_VIRTUALBOX)
#define KZEROMAPPER_ENABLE_VIRTUALBOX
#endif

// Aliases curtos quando habilitados
#if defined(KZEROMAPPER_ENABLE_CPUZ)
#define ENABLE_CPUZ
#endif
#if defined(KZEROMAPPER_ENABLE_DIRECTIO64)
#define ENABLE_DIRECTIO64
#endif
#if defined(KZEROMAPPER_ENABLE_KDMAPPER)
#define ENABLE_KDMAPPER
#endif
#if defined(KZEROMAPPER_ENABLE_KKYUM)
#define ENABLE_KKYUM
#endif
#if defined(KZEROMAPPER_ENABLE_RTCORE64)
#define ENABLE_RTCORE64
#endif
#if defined(KZEROMAPPER_ENABLE_VIRTUALBOX)
#define ENABLE_VIRTUALBOX
#endif
