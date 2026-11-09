import { useState } from "react";

// A star rating; hover previews, a click reports the pick through `onRate`.
export function Stars(props: { value: number; max: number; onRate: (n: number) => void }) {
  const [hover, setHover] = useState(0);
  const shown = hover || props.value;
  return (
    <div className="stars" role="radiogroup" onMouseLeave={() => setHover(0)}>
      {Array.from({ length: props.max }, (_, i) => i + 1).map((n) => (
        <button
          key={n}
          type="button"
          role="radio"
          aria-checked={n === props.value}
          aria-label={`${n} of ${props.max}`}
          className={n <= shown ? "star lit" : "star"}
          onMouseEnter={() => setHover(n)}
          onClick={() => props.onRate(n)}
        >
          ★
        </button>
      ))}
    </div>
  );
}
