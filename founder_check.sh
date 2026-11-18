#!/usr/bin/env bash
# founder_check.sh
# Java4Shell (CVE-2026-114938) - verificacao rapida de exposicao. (pt-BR)
#
# Rode em CADA servidor que atende os QRs dinamicos / retorna o JSON do payload.
# NAO envia nada pela rede, NAO explora nada, NAO altera nada. So le a versao do
# JDK e as flags da CPU e imprime um veredito.
#
#   bash founder_check.sh
#
# Codigos de saida: 0 = NAO exposto | 2 = EXPOSTO | 3 = indeterminado
set -u

echo "==================================================================="
echo " Java4Shell (CVE-2026-114938) - verificacao rapida"
echo " Host: $(hostname 2>/dev/null || echo '?')    Data: $(date 2>/dev/null || echo '?')"
echo "==================================================================="
echo

# Compara versoes 'pontuadas' (ex: 25.0.5 vs 25.0.5.1). Retorna 0 se $1 >= $2.
ver_ge() {
  local IFS=.
  local -a a=($1) b=($2)
  local i x y
  for i in 0 1 2 3; do
    x=${a[i]:-0}; y=${b[i]:-0}
    x=${x//[^0-9]/}; y=${y//[^0-9]/}
    x=${x:-0}; y=${y:-0}
    if [ "$((10#$x))" -gt "$((10#$y))" ]; then return 0; fi
    if [ "$((10#$x))" -lt "$((10#$y))" ]; then return 1; fi
  done
  return 0
}

# ------------------------------------------------------------------ JDK
JDK_STATUS="DESCONHECIDO"
JV_RAW="$(java -version 2>&1 | head -1)"
if [ -z "$JV_RAW" ]; then
  echo "[JDK] 'java' nao encontrado neste shell."
  echo "      -> rode no ambiente que executa a aplicacao, ou use o java do"
  echo "         JAVA_HOME do servico (ex: \$JAVA_HOME/bin/java -version)."
else
  echo "[JDK] $JV_RAW"
  VER="$(printf '%s' "$JV_RAW" | sed -E 's/[^"]*"([0-9][0-9.]*)".*/\1/')"
  MAJOR="${VER%%.*}"
  FIX=""; FLOOR=""
  case "$MAJOR" in
    17) FIX="17.0.21.1"; FLOOR="17.0.6" ;;
    21) FIX="21.0.13.1"; FLOOR="21" ;;
    25) FIX="25.0.5.1";  FLOOR="25" ;;
    27) FIX="27.0.1.1";  FLOOR="27" ;;
  esac
  if [ -z "$FIX" ]; then
    JDK_STATUS="NAO_AFETADO"
    echo "      Familia $MAJOR fora do escopo (afetados: 17.0.6+, 21, 25, 27)."
  elif ver_ge "$VER" "$FIX"; then
    JDK_STATUS="NAO_AFETADO"
    echo "      Build $VER >= correcao $FIX -> ja corrigido."
  elif ver_ge "$VER" "$FLOOR"; then
    JDK_STATUS="AFETADO"
    echo "      Build $VER na faixa vulneravel (correcao a partir de $FIX)."
  else
    JDK_STATUS="NAO_AFETADO"
    echo "      Build $VER anterior a $FLOOR -> sem o decoder vulneravel."
  fi
fi
echo

# ------------------------------------------------------------------ CPU
CPU_STATUS="DESCONHECIDO"
if [ -r /proc/cpuinfo ]; then
  if grep -qw avx512f /proc/cpuinfo && grep -qw avx512bw /proc/cpuinfo \
     && grep -qw avx512vbmi /proc/cpuinfo && grep -qw bmi2 /proc/cpuinfo; then
    CPU_STATUS="EM_RISCO"
    echo "[CPU] Flags AVX-512 presentes (avx512f/bw/vbmi + bmi2) -> EM RISCO."
  else
    CPU_STATUS="LIMPO"
    echo "[CPU] Sem o conjunto AVX-512 necessario -> LIMPO (ARM ou Intel/AMD sem AVX-512)."
  fi
else
  ARCH="$(uname -m 2>/dev/null || echo '?')"
  case "$ARCH" in
    arm64|aarch64) CPU_STATUS="LIMPO"
      echo "[CPU] Arquitetura $ARCH (ARM) -> LIMPO (nao usa o intrinsic AVX-512)." ;;
    *) CPU_STATUS="DESCONHECIDO"
      echo "[CPU] /proc/cpuinfo indisponivel (arch: $ARCH). Verifique manualmente:"
      echo "      ARM (Graviton/Apple) = limpo; Intel/AMD com AVX-512 = em risco." ;;
  esac
fi
echo

# ------------------------------------------------------------------ Veredito
echo "-------------------------------------------------------------------"
if [ "$JDK_STATUS" = "NAO_AFETADO" ] || [ "$CPU_STATUS" = "LIMPO" ]; then
  echo " EXPOSTO: NAO"
  [ "$JDK_STATUS" = "NAO_AFETADO" ] && echo "   Motivo: JDK fora da faixa vulneravel / ja corrigido."
  [ "$CPU_STATUS" = "LIMPO" ] && echo "   Motivo: CPU sem AVX-512 (o bug nao e alcancavel nesta maquina)."
  echo "-------------------------------------------------------------------"
  exit 0
elif [ "$JDK_STATUS" = "AFETADO" ] && [ "$CPU_STATUS" = "EM_RISCO" ]; then
  echo " EXPOSTO: SIM  (JDK vulneravel + CPU AVX-512)"
  echo "-------------------------------------------------------------------"
  echo " Acao recomendada (sem derrubar o servico):"
  echo "   1) Reinicie a JVM com a flag:  -XX:-UseBASE64Intrinsics"
  echo "      (neutraliza a falha na hora; reinicio rolling, sem downtime)"
  echo "   2) Depois, aplique o patch: 17.0.21.1 / 21.0.13.1 / 25.0.5.1 /"
  echo "      27.0.1.1 / 8u513-perf / Corretto 17.0.21.1.2."
  echo "   Desligar o servico so se nao der para reiniciar/patchar rapido."
  echo "-------------------------------------------------------------------"
  exit 2
else
  echo " EXPOSTO: INDETERMINADO (faltou confirmar JDK ou CPU)"
  echo "   JDK=$JDK_STATUS  CPU=$CPU_STATUS"
  echo "   Trate como potencialmente exposto ate confirmar os dois."
  echo "-------------------------------------------------------------------"
  exit 3
fi
