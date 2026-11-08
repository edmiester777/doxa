import { useState } from "react";

// A React component used from Rust: its props arrive as JSON, `onPick` calls back into Rust.
export function Count(props: { total: number; onPick: (shown: boolean) => void }) {
  const [shown, setShown] = useState(true);
  return (
    <button
      className="count"
      onClick={() => {
        setShown(!shown);
        props.onPick(!shown);
      }}
    >
      {shown ? `${props.total} widgets` : "show count"}
    </button>
  );
}
