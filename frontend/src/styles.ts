import type { CSSProperties } from "react";

export const colors = {
  bg: "#0a0a0a",
  card: "#1a1a1a",
  cardBorder: "#2a2a2a",
  primary: "#6366f1",
  primaryHover: "#818cf8",
  text: "#e5e5e5",
  textMuted: "#a3a3a3",
  success: "#22c55e",
  error: "#ef4444",
  warning: "#eab308",
  inputBg: "#111111",
  inputBorder: "#333333",
};

export const baseStyles = {
  page: {
    padding: "24px",
    maxWidth: "800px",
    margin: "0 auto",
  } satisfies CSSProperties,

  card: {
    background: colors.card,
    border: `1px solid ${colors.cardBorder}`,
    borderRadius: "12px",
    padding: "24px",
    marginBottom: "20px",
  } satisfies CSSProperties,

  h2: {
    color: colors.text,
    fontSize: "22px",
    fontWeight: 600,
    marginBottom: "20px",
    marginTop: 0,
  } satisfies CSSProperties,

  h3: {
    color: colors.text,
    fontSize: "16px",
    fontWeight: 600,
    marginBottom: "16px",
    marginTop: 0,
  } satisfies CSSProperties,

  label: {
    display: "block",
    color: colors.textMuted,
    fontSize: "13px",
    marginBottom: "6px",
    fontWeight: 500,
  } satisfies CSSProperties,

  input: {
    width: "100%",
    padding: "10px 12px",
    background: colors.inputBg,
    border: `1px solid ${colors.inputBorder}`,
    borderRadius: "8px",
    color: colors.text,
    fontSize: "14px",
    fontFamily: "monospace",
    outline: "none",
    boxSizing: "border-box" as const,
  } satisfies CSSProperties,

  textarea: {
    width: "100%",
    padding: "10px 12px",
    background: colors.inputBg,
    border: `1px solid ${colors.inputBorder}`,
    borderRadius: "8px",
    color: colors.text,
    fontSize: "13px",
    fontFamily: "monospace",
    outline: "none",
    resize: "vertical" as const,
    minHeight: "120px",
    boxSizing: "border-box" as const,
  } satisfies CSSProperties,

  select: {
    width: "100%",
    padding: "10px 12px",
    background: colors.inputBg,
    border: `1px solid ${colors.inputBorder}`,
    borderRadius: "8px",
    color: colors.text,
    fontSize: "14px",
    outline: "none",
    boxSizing: "border-box" as const,
  } satisfies CSSProperties,

  button: {
    padding: "12px 24px",
    background: colors.primary,
    color: "#ffffff",
    border: "none",
    borderRadius: "8px",
    fontSize: "14px",
    fontWeight: 600,
    cursor: "pointer",
    transition: "background 0.15s",
  } satisfies CSSProperties,

  buttonDisabled: {
    opacity: 0.5,
    cursor: "not-allowed",
  } satisfies CSSProperties,

  field: {
    marginBottom: "16px",
  } satisfies CSSProperties,

  resultBox: {
    padding: "16px",
    borderRadius: "8px",
    fontSize: "14px",
    fontFamily: "monospace",
    wordBreak: "break-all" as const,
    marginTop: "16px",
  } satisfies CSSProperties,

  successBox: {
    background: "#0a2015",
    border: `1px solid ${colors.success}`,
    color: colors.success,
  } satisfies CSSProperties,

  errorBox: {
    background: "#1a0a0a",
    border: `1px solid ${colors.error}`,
    color: colors.error,
  } satisfies CSSProperties,

  infoBox: {
    background: "#0a0a2a",
    border: `1px solid ${colors.primary}`,
    color: colors.text,
  } satisfies CSSProperties,

  detailRow: {
    display: "flex",
    justifyContent: "space-between",
    padding: "8px 0",
    borderBottom: `1px solid ${colors.cardBorder}`,
    fontSize: "14px",
  } satisfies CSSProperties,

  detailLabel: {
    color: colors.textMuted,
    fontWeight: 500,
  } satisfies CSSProperties,

  detailValue: {
    color: colors.text,
    fontFamily: "monospace",
    maxWidth: "60%",
    textAlign: "right" as const,
    wordBreak: "break-all" as const,
  } satisfies CSSProperties,
};
