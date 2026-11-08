import { StrictMode, useState } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, Link, Outlet, RouterProvider, useParams } from "react-router";
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { RenameWidget, WidgetPicker, WidgetTitle, configure } from "@widgets/kit";
import "@widgets/kit/style.css";

const queryClient = new QueryClient();

const router = createBrowserRouter([
  {
    path: "/",
    element: <Shell />,
    children: [
      { index: true, element: <Home /> },
      { path: "widgets/:name", element: <WidgetPage /> },
    ],
  },
]);

configure({
  token: () => "host-token",
  navigate: (to, { replace }) => router.navigate(to, { replace }),
  invalidated: (entities) =>
    entities.forEach((e) => queryClient.invalidateQueries({ queryKey: [e] })),
});

// The host's own read of the widgets, cached by react-query rather than doxa.
function HostList() {
  const { data } = useQuery({
    queryKey: ["Widget", "list"],
    queryFn: () => fetch("/api/widgets").then((r) => r.json()),
  });
  return <p className="host-list">{data?.map((w) => w.name).join(", ")}</p>;
}

function Shell() {
  return (
    <>
      <nav>
        <Link className="home" to="/">home</Link>
      </nav>
      <HostList />
      <Outlet />
    </>
  );
}

function Home() {
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

function WidgetPage() {
  const { name } = useParams();
  return (
    <main>
      <h1 className="host-page">{name}</h1>
      <RenameWidget name={name} to={`${name}-renamed`} />
    </main>
  );
}

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
);
