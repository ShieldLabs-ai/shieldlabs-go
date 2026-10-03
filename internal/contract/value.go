// Package contract provides schema-derived views of decoded API objects.
// Views preserve unknown fields and malformed values; normalization stays in
// the supported client instead of imposing stricter JSON validation.
package contract

// Object returns an object field without rejecting null or malformed values.
func Object[T any](v Value[T]) map[string]any {
	m, _ := v.Raw.(map[string]any)
	return m
}

// Array returns an array field without rejecting null or malformed values.
func Array[T any](v Value[[]T]) []any {
	items, _ := v.Raw.([]any)
	return items
}

// String returns only strings, as required for webhook envelope fields.
func String(v Value[string]) string {
	s, _ := v.Raw.(string)
	return s
}
