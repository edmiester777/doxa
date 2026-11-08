import type { ComponentType, ReactNode } from "react";

// A class Rust makes with `new`.
export class Tally {
  count: number;
  constructor(start: number) {
    this.count = start;
  }
  bump(): number {
    return ++this.count;
  }
}

// Plugins Rust passes along as values, never calls.
export default function shout(s: string): string {
  return s.toUpperCase();
}

export function exclaim(s: string): string {
  return s + "!";
}

// Applies its plugins in order, then renders each letter through `components.letter`.
export function Pipeline(props: {
  text: string;
  plugins: ((s: string) => string)[];
  components: {
    letter: ComponentType<{ letter: string; index: number; onClick: () => void; children: ReactNode }>;
  };
  icons: { done: ReactNode };
}) {
  const out = props.plugins.reduce((s, f) => f(s), props.text);
  const Letter = props.components.letter;
  return (
    <div className="pipeline">
      <p className="piped">{out}</p>
      <ul>
        {[...out].map((letter, index) => (
          <li key={index}>
            <Letter letter={letter} index={index} onClick={() => {}}>
              <em className="kid">{letter}</em>
            </Letter>
          </li>
        ))}
      </ul>
      <span className="done">{props.icons.done}</span>
    </div>
  );
}
