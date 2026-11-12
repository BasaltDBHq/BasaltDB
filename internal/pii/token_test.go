package pii_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/pii"
)

const idRe = `[A-Z2-7]{12}`

func mustToken(t *testing.T, k *pii.Keys, typ pii.EntityType, value, region string) pii.Token {
	t.Helper()
	tok, err := k.MakeToken(typ, value, region)
	require.NoError(t, err)
	return tok
}

func TestTokenShapes(t *testing.T) {
	k := newKeys(t, testMaster)
	cases := []struct {
		typ    pii.EntityType
		value  string
		region string
		re     string
	}{
		{pii.EntityEmail, "fixture.alice.tamm@gmail.com", "", `^pii1_` + idRe + `@gmail\.com$`},
		{pii.EntityEmail, "Fixture.Alice@GMAIL.com", "", `^pii1_` + idRe + `@gmail\.com$`},
		{pii.EntityEmail, "jaan@outlook.com", "", `^pii1_` + idRe + `@outlook\.com$`},
		{pii.EntityEmail, "mari.kask@fixture-corp.example", "", `^pii1_` + idRe + `@redacted\.invalid$`},
		{pii.EntityEmail, "no-at-sign", "", `^pii1_` + idRe + `@redacted\.invalid$`},
		{pii.EntityEmail, "x@sub.gmail.com", "", `^pii1_` + idRe + `@redacted\.invalid$`},
		{pii.EntityPhone, "+44 7700 900123", "", `^\+44 pii1_` + idRe + `$`},
		{pii.EntityPhone, "+372 5123 4567", "", `^\+372 pii1_` + idRe + `$`},
		{pii.EntityPhone, "0812-3456-7890", "ID", `^\+62 pii1_` + idRe + `$`},
		{pii.EntityPhone, "0812-3456-7890", "", `^pii1_` + idRe + `$`},
		{pii.EntityPersonName, "Alice Tamm", "", `^Person ` + idRe + `$`},
		{pii.EntityAddress, "12 Fixture Lane, Tallinn", "", `^Address ` + idRe + `$`},
		{pii.EntityOther, "DE89370400440532013000", "", `^pii1_` + idRe + `$`},
	}
	for _, c := range cases {
		got := mustToken(t, k, c.typ, c.value, c.region).Surface()
		require.Regexp(t, regexp.MustCompile(c.re), got, "%s %s", c.typ, c.region)
	}
}

func TestTokensAreDeterministicAndNormalized(t *testing.T) {
	k1 := newKeys(t, testMaster)
	k2 := newKeys(t, testMaster)
	k3 := newKeys(t, []byte("another-master-key-0123456789abc"))
	a := mustToken(t, k1, pii.EntityPersonName, "Alice Tamm", "")
	require.Equal(t, a, mustToken(t, k2, pii.EntityPersonName, "Alice Tamm", ""), "same key, same token")
	require.Equal(t, a, mustToken(t, k1, pii.EntityPersonName, "alice   TAMM", ""), "normalized")
	require.Equal(t, a, mustToken(t, k1, pii.EntityPersonName, "Alice\u200b Tamm", ""), "zero-width ignored")
	require.NotEqual(t, a.ID, mustToken(t, k3, pii.EntityPersonName, "Alice Tamm", "").ID, "key matters")
	addr := mustToken(t, k1, pii.EntityAddress, "Alice Tamm", "")
	require.NotEqual(t, a.ID[len("Person "):], addr.ID[len("Address "):], "type matters")

	require.Equal(t, mustToken(t, k1, pii.EntityPhone, "+44 7700 900123", ""), mustToken(t, k1, pii.EntityPhone, "+447700900123", ""))
	require.Equal(t, mustToken(t, k1, pii.EntityEmail, "A@Gmail.com", ""), mustToken(t, k1, pii.EntityEmail, "a@gmail.com", ""))
}

func TestTokensOfNFCAndNFDAreEqual(t *testing.T) {
	k := newKeys(t, testMaster)
	for _, typ := range pii.TokenTypes() {
		nfc := mustToken(t, k, typ, "José Pérez", "")
		nfd := mustToken(t, k, typ, "Jose\u0301 Pe\u0301rez", "")
		require.Equal(t, nfc, nfd, typ)
	}
}

func TestLocalFormatPhoneGetsTheSameTokenAsE164(t *testing.T) {
	k := newKeys(t, testMaster)
	e164 := mustToken(t, k, pii.EntityPhone, "+62 812-3456-7890", "")
	for _, local := range []string{"0812-3456-7890", "0812 3456 7890", "(0812) 34567890"} {
		require.Equal(t, e164, mustToken(t, k, pii.EntityPhone, local, "ID"), local)
	}
	require.NotEqual(t, e164.ID, mustToken(t, k, pii.EntityPhone, "0812-3456-7890", "").ID, "no region: not the same number")
}

func TestEveryTokenIDHasTwelveBase32Characters(t *testing.T) {
	k := newKeys(t, testMaster)
	for _, typ := range pii.TokenTypes() {
		tok := mustToken(t, k, typ, "value", "")
		require.Regexp(t, idRe+`$`, tok.ID, typ)
	}
}

func TestMakeTokenRefusesAnUnknownType(t *testing.T) {
	_, err := newKeys(t, testMaster).MakeToken(pii.EntityType("SSN"), "x", "")
	require.Error(t, err)
}

func TestTokenStringNeverHoldsTheValue(t *testing.T) {
	tok := mustToken(t, newKeys(t, testMaster), pii.EntityEmail, "secret.person@gmail.com", "")
	for _, s := range []string{tok.String(), fmt.Sprintf("%v %+v %#v", tok, tok, tok)} {
		require.NotContains(t, s, "secret.person")
	}
}
