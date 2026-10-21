#!/bin/sh
# Échoue si la couverture d'un paquet passe sous son plancher.
# .couverture-min : une ligne « fichier.cover plancher » par paquet ; les lignes
# vides et celles qui commencent par # sont ignorées.
# Les planchers se remontent à la main quand la couverture progresse, jamais
# automatiquement : une baisse doit toujours être un choix visible.
set -eu
statut=0
while read -r profil plancher; do
	case "$profil" in
	'' | '#'*) continue ;;
	esac
	reel=$(go tool cover -func="$profil" | tail -1 | awk '{ sub("%", "", $NF); print $NF }')
	if awk -v r="$reel" -v m="$plancher" 'BEGIN { exit !(r < m) }'; then
		echo "couverture ($profil) : $reel % < plancher $plancher %"
		statut=1
	else
		echo "couverture ($profil) : $reel % (plancher $plancher %)"
	fi
done < .couverture-min
exit $statut
