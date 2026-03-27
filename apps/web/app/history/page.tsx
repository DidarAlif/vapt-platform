"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import AuthenticatedLayout from "../../components/AuthenticatedLayout";

interface Scan {
    id: string;
    target_url: string;
    scan_mode: string;
    created_at: string;
    risk_score: number;
}

export default function HistoryPage() {
    const router = useRouter();
    const [scans, setScans] = useState<Scan[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    useEffect(() => {
        const token = localStorage.getItem("access_token");
        if (!token) {
            router.push("/login");
            return;
        }
        fetchScans(token);
    }, [router]);

    const fetchScans = async (token: string) => {
        try {
            const baseUrl = (process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000").replace(/\/$/, "");
            const response = await fetch(`${baseUrl}/scans`, {
                headers: { Authorization: `Bearer ${token}` },
            });

            if (response.status === 401) {
                localStorage.clear();
                router.push("/login");
                return;
            }

            const data = await response.json();
            setScans(data);
        } catch {
            setError("Failed to load scan history");
        } finally {
            setLoading(false);
        }
    };

    const deleteScan = async (scanId: string) => {
        const token = localStorage.getItem("access_token");
        if (!token) return;

        try {
            const baseUrl = (process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000").replace(/\/$/, "");
            await fetch(`${baseUrl}/scans/${scanId}`, {
                method: "DELETE",
                headers: { Authorization: `Bearer ${token}` },
            });
            setScans(scans.filter(s => s.id !== scanId));
        } catch {
            setError("Failed to delete scan");
        }
    };

    const getRiskBadge = (score: number) => {
        if (score >= 70) return { text: "CRITICAL", classes: "bg-error-container text-on-error-container" };
        if (score >= 40) return { text: "HIGH", classes: "bg-tertiary-container text-on-tertiary-container" };
        if (score >= 20) return { text: "MEDIUM", classes: "bg-[#ffcc00] text-surface" };
        return { text: "LOW", classes: "bg-emerald-500/20 text-emerald-400" };
    };

    const getModeIcon = (mode: string) => {
        const icons: Record<string, string> = {
            quick: "bolt", full: "vitals", network: "hub", custom: "tune"
        };
        return icons[mode] || "radar";
    };

    return (
        <AuthenticatedLayout>
            <div className="max-w-6xl mx-auto px-10 py-12">
                <div className="mb-10 flex justify-between items-end">
                    <div>
                        <h1 className="text-3xl font-headline font-bold text-on-surface tracking-tight">
                            Scan History
                        </h1>
                        <p className="text-on-surface-variant font-body mt-1">
                            Complete archive of previous reconnaissance operations.
                        </p>
                    </div>
                    <div className="flex gap-3">
                        <div className="flex items-center gap-2 bg-surface-container-low px-4 py-2 rounded-lg border border-outline-variant/10">
                            <span className="material-symbols-outlined text-primary text-sm">database</span>
                            <span className="text-[10px] font-headline font-bold text-on-surface-variant uppercase">
                                {scans.length} Records
                            </span>
                        </div>
                    </div>
                </div>

                {loading ? (
                    <div className="text-center py-20 text-on-surface-variant font-headline text-sm">
                        Loading scan history...
                    </div>
                ) : error ? (
                    <div className="bg-error-container/20 border border-error/30 rounded-xl p-6 flex items-center gap-3">
                        <span className="material-symbols-outlined text-error">error</span>
                        <span className="text-error text-sm">{error}</span>
                    </div>
                ) : scans.length === 0 ? (
                    <div className="text-center py-20">
                        <span className="material-symbols-outlined text-5xl text-slate-600 mb-4 block">
                            history
                        </span>
                        <p className="text-on-surface-variant text-sm mb-4">No scans recorded yet</p>
                        <Link
                            href="/scan"
                            className="inline-flex items-center gap-2 bg-primary-container text-on-primary-container px-6 py-3 rounded-xl font-headline font-bold active:scale-95 transition-transform"
                        >
                            <span className="material-symbols-outlined">radar</span>
                            Start First Scan
                        </Link>
                    </div>
                ) : (
                    <section className="bg-surface-container-low rounded-xl overflow-hidden">
                        <div className="overflow-x-auto">
                            <table className="w-full text-left">
                                <thead className="bg-surface-container-lowest text-slate-500 uppercase font-headline font-bold text-[9px] tracking-[0.15em]">
                                    <tr>
                                        <th className="px-8 py-4">Analysis Target</th>
                                        <th className="px-8 py-4">Mode</th>
                                        <th className="px-8 py-4 text-center">Risk Vector</th>
                                        <th className="px-8 py-4">Date</th>
                                        <th className="px-8 py-4 text-right">Operations</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-outline-variant/10 text-on-surface-variant text-xs">
                                    {scans.map((scan) => {
                                        const risk = getRiskBadge(scan.risk_score);
                                        return (
                                            <tr key={scan.id} className="hover:bg-surface-container transition-colors group">
                                                <td className="px-8 py-4">
                                                    <div className="flex items-center gap-3">
                                                        <div className="w-8 h-8 rounded bg-surface-container-high flex items-center justify-center text-primary">
                                                            <span className="material-symbols-outlined text-sm">
                                                                {getModeIcon(scan.scan_mode)}
                                                            </span>
                                                        </div>
                                                        <div>
                                                            <p className="font-headline font-bold text-on-surface">
                                                                {scan.target_url}
                                                            </p>
                                                        </div>
                                                    </div>
                                                </td>
                                                <td className="px-8 py-4">
                                                    <span className="font-headline text-on-surface-variant capitalize">
                                                        {scan.scan_mode}
                                                    </span>
                                                </td>
                                                <td className="px-8 py-4 text-center">
                                                    <span className={`text-[9px] font-headline font-bold px-2 py-0.5 rounded ${risk.classes}`}>
                                                        {risk.text} ({scan.risk_score})
                                                    </span>
                                                </td>
                                                <td className="px-8 py-4 font-headline text-slate-500">
                                                    {new Date(scan.created_at).toLocaleDateString("en-US", {
                                                        year: "numeric",
                                                        month: "short",
                                                        day: "numeric",
                                                    })}
                                                </td>
                                                <td className="px-8 py-4 text-right">
                                                    <button
                                                        onClick={() => deleteScan(scan.id)}
                                                        className="p-2 rounded hover:bg-error/10 transition-colors text-slate-500 hover:text-error"
                                                        title="Delete scan"
                                                    >
                                                        <span className="material-symbols-outlined text-lg">delete</span>
                                                    </button>
                                                </td>
                                            </tr>
                                        );
                                    })}
                                </tbody>
                            </table>
                        </div>
                    </section>
                )}
            </div>
        </AuthenticatedLayout>
    );
}
