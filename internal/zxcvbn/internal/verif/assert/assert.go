// Package assert remplace le strict nécessaire de testify/assert pour les
// tests de la copie de zxcvbn : cinq vérifications, aucune dépendance.
package assert

import (
	"fmt"
	"reflect"
	"testing"
)

// message assemble le message facultatif (format puis arguments).
func message(msgAndArgs []any) string {
	switch len(msgAndArgs) {
	case 0:
		return ""
	case 1:
		return fmt.Sprint(msgAndArgs[0])
	default:
		if format, ok := msgAndArgs[0].(string); ok {
			return fmt.Sprintf(format, msgAndArgs[1:]...)
		}
		return fmt.Sprint(msgAndArgs...)
	}
}

func fail(t testing.TB, msgAndArgs []any, format string, args ...any) bool {
	t.Helper()
	text := fmt.Sprintf(format, args...)
	if extra := message(msgAndArgs); extra != "" {
		text += "\n" + extra
	}
	t.Error(text)
	return false
}

// Equal vérifie l'égalité profonde (reflect.DeepEqual).
func Equal(t testing.TB, expected, actual any, msgAndArgs ...any) bool {
	t.Helper()
	if reflect.DeepEqual(expected, actual) {
		return true
	}
	return fail(t, msgAndArgs, "valeurs différentes\nattendu : %#v\nobtenu  : %#v", expected, actual)
}

// EqualValues comme Equal, mais convertit d'abord la valeur attendue vers le
// type de la valeur obtenue quand c'est possible (int 3 et float64 3.0).
func EqualValues(t testing.TB, expected, actual any, msgAndArgs ...any) bool {
	t.Helper()
	if reflect.DeepEqual(expected, actual) {
		return true
	}
	if expected != nil && actual != nil {
		expectedValue := reflect.ValueOf(expected)
		actualType := reflect.TypeOf(actual)
		if expectedValue.Type().ConvertibleTo(actualType) &&
			reflect.DeepEqual(expectedValue.Convert(actualType).Interface(), actual) {
			return true
		}
	}
	return fail(t, msgAndArgs, "valeurs différentes\nattendu : %#v\nobtenu  : %#v", expected, actual)
}

// Empty vérifie que la valeur est vide : nil, valeur zéro, ou
// tableau/tranche/table/chaîne/canal de longueur 0.
func Empty(t testing.TB, object any, msgAndArgs ...any) bool {
	t.Helper()
	if isEmpty(object) {
		return true
	}
	return fail(t, msgAndArgs, "devrait être vide, obtenu : %#v", object)
}

func isEmpty(object any) bool {
	if object == nil {
		return true
	}
	value := reflect.ValueOf(object)
	switch value.Kind() {
	case reflect.Chan, reflect.Map, reflect.Slice, reflect.String, reflect.Array:
		return value.Len() == 0
	case reflect.Ptr:
		if value.IsNil() {
			return true
		}
		return isEmpty(value.Elem().Interface())
	default:
		return value.IsZero()
	}
}

// Len vérifie la longueur d'une tranche, table, chaîne, tableau ou canal.
func Len(t testing.TB, object any, length int, msgAndArgs ...any) bool {
	t.Helper()
	value := reflect.ValueOf(object)
	switch value.Kind() {
	case reflect.Chan, reflect.Map, reflect.Slice, reflect.String, reflect.Array:
	default:
		return fail(t, msgAndArgs, "%#v n'a pas de longueur", object)
	}
	if value.Len() == length {
		return true
	}
	return fail(t, msgAndArgs, "longueur attendue %d, obtenue %d", length, value.Len())
}

// True vérifie que la condition est vraie.
func True(t testing.TB, value bool, msgAndArgs ...any) bool {
	t.Helper()
	if value {
		return true
	}
	return fail(t, msgAndArgs, "devrait être vrai")
}
