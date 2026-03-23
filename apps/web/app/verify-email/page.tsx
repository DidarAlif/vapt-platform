"use client";

import { useState, useEffect, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import Image from "next/image";

const API_URL = (process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

function VerifyEmailContent() {
    const router = useRouter();
    const searchParams = useSearchParams();
    const token = searchParams.get("token");
    const pending = searchParams.get("pending");

    const [status, setStatus] = useState<"pending" | "verifying" | "success" | "error">(
        token && !pending ? "verifying" : "pending"
    );
    const [error, setError] = useState("");
    const [email, setEmail] = useState(searchParams.get("email") || "");
    const [otp, setOtp] = useState("");
    const [resendLoading, setResendLoading] = useState(false);
    const [resendSuccess, setResendSuccess] = useState(false);

    useEffect(() => {
        const userData = localStorage.getItem("user");
        if (userData && !email) {
            try {
                const user = JSON.parse(userData);
                setEmail(user.email);
            } catch { }
        }

        if (token && status === "verifying") {
            verifyEmailTokenString(token);
        }
    }, [token, status]);

    const verifyEmailTokenString = async (verificationToken: string) => {
        setStatus("verifying");
        try {
            const response = await fetch(`${API_URL}/auth/verify-email`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ token: verificationToken }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || "Verification failed");
            }

            // Successfully verified! Save the newly issued access tokens explicitly now.
            localStorage.setItem("access_token", data.access_token);
            localStorage.setItem("refresh_token", data.refresh_token);
            localStorage.setItem("user", JSON.stringify(data.user));

            setStatus("success");
        } catch (err) {
            setError(err instanceof Error ? err.message : "Verification failed");
            setStatus("error");
        }
    };

    const handleVerifySubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (otp.length !== 6) {
            setError("Please enter the 6-digit OTP");
            setStatus("error");
            return;
        }
        verifyEmailTokenString(otp);
    };

    const handleResend = async () => {
        if (!email) return;

        setResendLoading(true);
        setResendSuccess(false);

        try {
            const response = await fetch(`${API_URL}/auth/resend-verification`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email }),
            });

            if (response.ok) {
                setResendSuccess(true);
            }
        } catch (err) {
            console.error("Resend error:", err);
        } finally {
            setResendLoading(false);
        }
    };

    const handleLogout = () => {
        localStorage.removeItem("access_token");
        localStorage.removeItem("refresh_token");
        localStorage.removeItem("user");
        router.push("/login");
    };

    return (
        <div className="w-full max-w-md text-center">
            <div className="w-16 h-16 mx-auto relative mb-6">
                <Image src="/logo.png" alt="ReconScience" fill className="object-contain" />
            </div>

            {(status === "pending" || status === "error") && (
                <form onSubmit={handleVerifySubmit} className="bg-[#12121a] border border-gray-800/50 rounded-lg p-6">
                    <div className="w-12 h-12 mx-auto mb-4 rounded-full bg-[#00d4aa]/10 flex items-center justify-center">
                        <svg className="w-6 h-6 text-[#00d4aa]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                        </svg>
                    </div>
                    <h1 className="text-xl font-bold text-gray-100 mb-2">Check Your Email</h1>
                    <p className="text-gray-400 text-sm mb-6">
                        We've sent a 6-digit verification code to <br/>
                        <span className="text-[#00d4aa] font-mono">{email}</span><br/>
                        Please enter it below.
                    </p>

                    {status === "error" && (
                        <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
                            {error}
                        </div>
                    )}

                    <div className="mb-6">
                        <input
                            type="text"
                            value={otp}
                            onChange={(e) => setOtp(e.target.value.replace(/[^0-9]/g, '').slice(0, 6))}
                            required
                            placeholder="• • • • • •"
                            className="w-full text-center tracking-[0.5em] font-mono text-3xl bg-[#0a0a0f] border border-gray-800 rounded-lg px-2 py-4 text-[#00d4aa] placeholder-gray-600 focus:border-[#00d4aa]/50 focus:ring-1 focus:ring-[#00d4aa]/20 transition-all font-bold"
                        />
                    </div>

                    <div className="space-y-3">
                        <button
                            type="submit"
                            className="w-full py-2.5 bg-[#00d4aa] hover:bg-[#00b894] text-[#0a0a0f] font-semibold rounded-lg transition-all"
                        >
                            Verify Email
                        </button>
                        <button
                            type="button"
                            onClick={handleResend}
                            disabled={resendLoading || resendSuccess || !email}
                            className="w-full py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-200 font-medium rounded-lg transition-all disabled:opacity-50"
                        >
                            {resendLoading ? "Sending..." : resendSuccess ? "OTP Sent!" : "Resend Code"}
                        </button>
                        <button
                            type="button"
                            onClick={handleLogout}
                            className="w-full py-2 text-gray-500 hover:text-gray-400 text-sm font-medium transition-all"
                        >
                            Use Different Email
                        </button>
                    </div>
                </form>
            )}

            {status === "verifying" && (
                <div className="bg-[#12121a] border border-gray-800/50 rounded-lg p-6">
                    <div className="w-12 h-12 mx-auto mb-4 rounded-full bg-[#00d4aa]/10 flex items-center justify-center">
                        <svg className="w-6 h-6 text-[#00d4aa] animate-spin" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                        </svg>
                    </div>
                    <h1 className="text-xl font-bold text-gray-100 mb-2">Verifying Code</h1>
                    <p className="text-gray-400 text-sm">Please wait...</p>
                </div>
            )}

            {status === "success" && (
                <div className="bg-[#12121a] border border-gray-800/50 rounded-lg p-6">
                    <div className="w-12 h-12 mx-auto mb-4 rounded-full bg-emerald-500/10 flex items-center justify-center">
                        <svg className="w-6 h-6 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                        </svg>
                    </div>
                    <h1 className="text-xl font-bold text-gray-100 mb-2">Email Verified!</h1>
                    <p className="text-gray-400 text-sm mb-6">Your account is now active. You can start scanning.</p>
                    <Link
                        href="/scan"
                        className="block w-full py-2.5 bg-[#00d4aa] hover:bg-[#00b894] text-[#0a0a0f] font-semibold rounded-lg transition-all text-center"
                    >
                        Go to Scanner
                    </Link>
                </div>
            )}

            <p className="mt-6 text-gray-600 text-xs">
                © 2026 Alif. All rights reserved.
            </p>
        </div>
    );
}

export default function VerifyEmailPage() {
    return (
        <div className="min-h-screen bg-[#0a0a0f] flex items-center justify-center px-4">
            <Suspense fallback={
                <div className="w-full max-w-md text-center">
                    <div className="bg-[#12121a] border border-gray-800/50 rounded-lg p-6">
                        <div className="w-12 h-12 mx-auto mb-4 rounded-full bg-[#00d4aa]/10 flex items-center justify-center">
                            <svg className="w-6 h-6 text-[#00d4aa] animate-spin" fill="none" viewBox="0 0 24 24">
                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                            </svg>
                        </div>
                        <p className="text-gray-400 text-sm">Loading...</p>
                    </div>
                </div>
            }>
                <VerifyEmailContent />
            </Suspense>
        </div>
    );
}
