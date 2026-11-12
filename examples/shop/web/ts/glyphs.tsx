// Icon components sharing one props shape, used from Rust as one enum.
type Props = { size?: number; strokeWidth?: number; color?: string; className?: string };

function Glyph(props: Props & { d: string; name: string }) {
  const size = props.size ?? 24;
  return (
    <svg
      className={["glyph", props.name, props.className].filter(Boolean).join(" ")}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke={props.color ?? "currentColor"}
      strokeWidth={props.strokeWidth ?? 2}
    >
      <path d={props.d} />
    </svg>
  );
}

export const Plus = (p: Props) => <Glyph {...p} name="plus" d="M5 12h14M12 5v14" />;
export const Minus = (p: Props) => <Glyph {...p} name="minus" d="M5 12h14" />;
