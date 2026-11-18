package schema

import (
	"fmt"
	"strings"
)

// ColumnCase selects how field names become column names when a field has no explicit column name.
type ColumnCase string

const (
	// Snake is goauth's historical layout (email_verified, user_id) and the default: it produces exactly the
	// column names GORM derives from the models' Go field names, so existing databases keep working.
	Snake ColumnCase = "snake"
	// Camel is better-auth's default Kysely/Drizzle/Prisma layout (emailVerified, userId); use it to share a
	// database with a TypeScript better-auth server.
	Camel ColumnCase = "camel"
)

// normalize returns the effective case ("" = Snake) or an error for unknown values.
func (c ColumnCase) normalize() (ColumnCase, error) {
	switch ColumnCase(strings.ToLower(string(c))) {
	case "", Snake:
		return Snake, nil
	case Camel:
		return Camel, nil
	}
	return "", fmt.Errorf("schema: unknown column case %q (use %q or %q)", c, Snake, Camel)
}

// column returns the column name of field under this case.
func (c ColumnCase) column(field string) string {
	if c == Camel {
		return field
	}
	return SnakeCase(field)
}

// commonInitialisms is GORM's list (gorm.io/gorm/schema/naming.go), in the same order, so that SnakeCase
// gives the same result as GORM's NamingStrategy for every Go field name of the models.
var commonInitialisms = []string{"API", "ASCII", "CPU", "CSS", "DNS", "EOF", "GUID", "HTML", "HTTP", "HTTPS", "ID", "IP", "JSON", "LHS", "QPS", "RAM", "RHS", "RPC", "SLA", "SMTP", "SSH", "TLS", "TTL", "UID", "UI", "UUID", "URI", "URL", "UTF8", "VM", "XML", "XSRF", "XSS"}

// initialismsReplacer turns "ID" into "Id" etc. before splitting words, like GORM.
var initialismsReplacer = func() *strings.Replacer {
	pairs := make([]string, 0, 2*len(commonInitialisms))
	for _, in := range commonInitialisms {
		pairs = append(pairs, in, in[:1]+strings.ToLower(in[1:]))
	}
	return strings.NewReplacer(pairs...)
}()

// SnakeCase converts a camelCase field name ("emailVerified", "lastLoginIP") to the snake_case column GORM
// would derive from the matching Go field name ("email_verified", "last_login_ip"). It is a port of GORM's
// NamingStrategy.toDBName applied to the name with its first letter upper-cased.
func SnakeCase(name string) string {
	if name == "" {
		return ""
	}
	// Step 1: GORM converts Go (exported) names; upper-case the first letter so "userId" behaves as "UserId"
	value := initialismsReplacer.Replace(strings.ToUpper(name[:1]) + name[1:])
	isUpper := func(b byte) bool { return b >= 'A' && b <= 'Z' }
	isDigit := func(b byte) bool { return b >= '0' && b <= '9' }

	// Step 2: walk the name and insert "_" before every upper-case letter that starts a word
	var (
		buf                            strings.Builder
		lastCase, nextCase, nextNumber bool
		curCase                        = isUpper(value[0])
	)
	for i := 0; i < len(value)-1; i++ {
		v := value[i]
		nextCase = isUpper(value[i+1])
		nextNumber = isDigit(value[i+1])
		if curCase {
			if lastCase && (nextCase || nextNumber) {
				buf.WriteByte(v + 32)
			} else {
				if i > 0 && value[i-1] != '_' && value[i+1] != '_' {
					buf.WriteByte('_')
				}
				buf.WriteByte(v + 32)
			}
		} else {
			buf.WriteByte(v)
		}
		lastCase = curCase
		curCase = nextCase
	}

	// Step 3: the last character
	last := value[len(value)-1]
	if curCase {
		if !lastCase && len(value) > 1 {
			buf.WriteByte('_')
		}
		buf.WriteByte(last + 32)
	} else {
		buf.WriteByte(last)
	}
	return buf.String()
}
