"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import Image from "next/image";

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
            const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000"}/scans`, {
                headers: { Authorization: `Bearer ${token}` },
            });

            if (response.status === 401) {
                localStorage.clear();
                router.push("/login");
                return;
            }

            const data = await response.json();
            setScans(data);
        } catch (err) {
            setError("Failed to load scan history");
        } finally {
            setLoading(false);
        }
    };

    const deleteScan = async (scanId: string) => {
        const token = localStorage.getItem("access_token");
        if (!token) return;

        try {
            await fetch(`${process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000"}/scans/${scanId}`, {
                method: "DELETE",
                headers: { Authorization: `Bearer ${token}` },
            });
            setScans(scans.filter(s => s.id !== scanId));
        } catch (err) {
            setError("Failed to delete scan");
        }
    };

    const getRiskColor = (score: number) => {
        if (score >= 70) return "text-red-400";
        if (score >= 40) return "text-orange-400";
        if (score >= 20) return "text-yellow-400";
        return "text-emerald-400";
    };

    const handleLogout = () => {
        localStorage.clear();
        router.push("/login");
    };

    return (
        <div className="min-h-screen bg-[#0a0a0f] text-gray-100">
            {/* Header */}
            <header className="border-b border-gray-800/50 px-6 py-4">
                <div className="max-w-7xl mx-auto flex items-center justify-between">
                    <Link href="/scan" className="flex items-center gap-3">
                        <div className="w-10 h-10 relative">
                            <Image src="/logo.png" alt="ReconScience" fill className="object-contain" />
                        </div>
                        <span className="text-xl font-bold text-[#00d4aa]">ReconScience</span>
                    </Link>
                    <div className="flex items-center gap-4">
                        <Link href="/scan" className="text-gray-400 hover:text-gray-200 text-sm">New Scan</Link>
                        <button onClick={handleLogout} className="text-gray-400 hover:text-red-400 text-sm">Logout</button>
                    </div>
                </div>
            </header>

            <main className="max-w-7xl mx-auto px-6 py-8">
                <h1 className="text-xl font-bold mb-6">Scan History</h1>

                {loading ? (
                    <div className="text-center py-12 text-gray-500 font-mono text-sm">Loading...</div>
                ) : error ? (
                    <div className="text-center py-12 text-red-400 text-sm">{error}</div>
                ) : scans.length === 0 ? (
                    <div className="text-center py-12">
                        <div className="w-12 h-12 mx-auto mb-4 rounded-full bg-gray-800 flex items-center justify-center">
                            <svg className="w-6 h-6 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                            </svg>
                        </div>
                        <p className="text-gray-400 text-sm">No scans yet</p>
                        <Link href="/scan" className="inline-block mt-4 px-6 py-2 bg-[#00d4aa] hover:bg-[#00b894] text-[#0a0a0f] rounded-lg text-sm font-medium">
                            Start First Scan
                        </Link>
                    </div>
                ) : (
                    <div className="bg-[#12121a] border border-gray-800/50 rounded-lg overflow-hidden">
                        <table className="w-full">
                            <thead>
                                <tr className="bg-[#0a0a0f]">
                                    <th className="px-4 py-3 text-left text-xs text-gray-500 uppercase">Target</th>
                                    <th className="px-4 py-3 text-left text-xs text-gray-500 uppercase">Mode</th>
                                    <th className="px-4 py-3 text-left text-xs text-gray-500 uppercase">Risk</th>
                                    <th className="px-4 py-3 text-left text-xs text-gray-500 uppercase">Date</th>
                                    <th className="px-4 py-3 text-left text-xs text-gray-500 uppercase">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-800">
                                {scans.map((scan) => (
                                    <tr key={scan.id} className="hover:bg-white/[0.02]">
                                        <td className="px-4 py-3 font-mono text-sm text-[#00d4aa]">{scan.target_url}</td>
                                        <td className="px-4 py-3 text-sm text-gray-300 capitalize">{scan.scan_mode}</td>
                                        <td className="px-4 py-3">
                                            <span className={`font-bold ${getRiskColor(scan.risk_score)}`}>{scan.risk_score}</span>
                                        </td>
                                        <td className="px-4 py-3 text-sm text-gray-500">
                                            {new Date(scan.created_at).toLocaleDateString()}
                                        </td>
                                        <td className="px-4 py-3">
                                            <button
                                                onClick={() => deleteScan(scan.id)}
                                                className="text-red-400 hover:text-red-300 text-sm"
                                            >
                                                Delete
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </main>
        </div>
    );
}
