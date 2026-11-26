import { useId } from "react";
import type { ReactNode } from "react";
import { AlertCircle } from "lucide-react";

export interface ColumnDef<T> {
  key: string;
  label: string;
  render: (row: T) => ReactNode;
}

export function DataTable<T>({
  caption,
  rows,
  columns,
  emptyMessage = "No records match the current filter.",
  loading = false,
  error = null,
  rowKey,
}: {
  caption: string;
  rows: T[];
  columns: Array<ColumnDef<T>>;
  emptyMessage?: string;
  loading?: boolean;
  error?: string | null;
  rowKey: (row: T, index: number) => string;
}) {
  const captionId = useId();

  if (error) {
    return (
      <div
        role="alert"
        className="edr-panel rounded-md border border-[#D63A46]/60 bg-[#D63A46]/10 p-4 text-sm text-[#FF9CA4] flex items-center gap-2"
      >
        <AlertCircle className="w-4 h-4 shrink-0" aria-hidden="true" />
        <span>{error}</span>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="edr-panel rounded-md border border-[#303139] bg-[#17181D] p-6 text-sm text-[#9A9CA6]">
        Loading {caption.toLowerCase()}...
      </div>
    );
  }

  return (
    <div tabIndex={0} role="region" aria-labelledby={captionId} className="table-wrapper">
      <table className="edr-table">
        <caption id={captionId}>{caption}</caption>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} scope="col">
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="text-center py-8 text-[#9A9CA6]">
                {emptyMessage}
              </td>
            </tr>
          ) : (
            rows.map((row, idx) => (
              <tr key={rowKey(row, idx)}>
                {columns.map((c) => (
                  <td key={c.key} data-label={c.label}>
                    {c.render(row)}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
