import { StrictMode, useState } from "react";
import { createRoot } from "react-dom/client";
import { WidgetPicker, WidgetTitle, configure } from "@widgets/kit";
import "@widgets/kit/style.css";

configure({ token: () => "host-token" });

function App() {
  const [open, setOpen] = useState(null);
  const [filter, setFilter] = useState("");
  return (
    <main>
      <input className="filter" value={filter} onChange={(e) => setFilter(e.target.value)} />
      <WidgetPicker contains={filter || undefined} onOpen={setOpen} />
      {open && <WidgetTitle name={open} level={2} />}
      <button className="open">outside the kit</button>
      {open && <button className="close" onClick={() => setOpen(null)}>close</button>}
    </main>
  );
}

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
