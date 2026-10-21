#!/bin/sh
# Échoue si la couverture d'un paquet passe sous son plancher.
# .couverture-min : une ligne « fichier.cover plancher » par paquet ; les lignes
# vides et celles qui commencent par # sont ignorées.
# Les planchers se remontent à la main quand la couverture progresse, jamais
# automatiquement : une baisse doit toujours être un choix visible.
# Le contrôle ne passe jamais en silence : plancher invalide, profil illisible
# ou aucune ligne vérifiée font échouer le script.
set -eu
statut=0
verifies=0
# « || [ -n "$profil" ] » : lit aussi une dernière ligne sans retour à la ligne.
while read -r profil plancher || [ -n "$profil" ]; do
	case "$profil" in
	'' | '#'*) continue ;;
	esac
	case "$plancher" in
	'' | *[!0-9.]*)
		echo "plancher invalide pour $profil : « $plancher »"
		exit 1
		;;
	esac
	sortie=$(go tool cover -func="$profil") || {
		echo "profil illisible : $profil"
		exit 1
	}
	reel=$(echo "$sortie" | tail -1 | awk '{ sub("%", "", $NF); print $NF }')
	case "$reel" in
	'' | *[!0-9.]*)
		echo "couverture introuvable dans le profil : $profil"
		exit 1
		;;
	esac
	verifies=$((verifies + 1))
	if awk -v r="$reel" -v m="$plancher" 'BEGIN { exit !(r < m) }'; then
		echo "couverture ($profil) : $reel % < plancher $plancher %"
		statut=1
	else
		echo "couverture ($profil) : $reel % (plancher $plancher %)"
	fi
done < .couverture-min
if [ "$verifies" -eq 0 ]; then
	echo "aucun plancher vérifié : .couverture-min est vide ou ne contient que des commentaires"
	exit 1
fi
exit $statut
