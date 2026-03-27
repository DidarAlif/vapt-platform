"use client";

import { useState, useEffect, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";

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
            <div className="w-12 h-12 mx-auto bg-primary-container rounded-xl flex items-center justify-center mb-6">
                <span
                    className="material-symbols-outlined text-on-primary-container text-2xl"
                    style={{ fontVariationSettings: "'FILL' 1" }}
                >
                    radar
                </span>
            </div>

            {(status === "pending" || status === "error") && (
                <form
                    onSubmit={handleVerifySubmit}
                    className="bg-surface-container-low border border-outline-variant/10 rounded-2xl p-8"
                >
                    <div className="w-14 h-14 mx-auto mb-5 rounded-2xl bg-primary/10 flex items-center justify-center">
                        <span className="material-symbols-outlined text-primary text-2xl">mail</span>
                    </div>
                    <h1 className="text-xl font-headline font-bold text-on-surface mb-2">Check Your Email</h1>
                    <p className="text-on-surface-variant text-sm mb-6 font-body">
                        We&apos;ve sent a 6-digit verification code to <br />
                        <span className="text-primary font-mono font-medium">{email}</span><br />
                        Please enter it below.
                    </p>

                    {status === "error" && (
                        <div className="mb-5 p-4 bg-error-container/20 border border-error/30 rounded-xl text-error text-sm flex items-center gap-2">
                            <span className="material-symbols-outlined text-sm">error</span>
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
                            className="w-full text-center tracking-[0.5em] font-mono text-3xl bg-surface-container-lowest border border-outline-variant/20 rounded-xl px-2 py-4 text-primary placeholder:text-slate-600 focus:border-primary focus:ring-1 focus:ring-primary/20 transition-all font-bold outline-none"
                        />
                    </div>

                    <div className="space-y-3">
                        <button
                            type="submit"
                            className="w-full py-3.5 bg-primary-container hover:bg-[#8433c4] text-on-primary-container font-headline font-bold rounded-xl transition-all active:scale-[0.98]"
                        >
                            Verify Email
                        </button>
                        <button
                            type="button"
                            onClick={handleResend}
                            disabled={resendLoading || resendSuccess || !email}
                            className="w-full py-3 bg-surface-container-high hover:bg-surface-container-highest text-on-surface font-headline font-medium rounded-xl transition-all disabled:opacity-50"
                        >
                            {resendLoading ? "Sending..." : resendSuccess ? "OTP Sent!" : "Resend Code"}
                        </button>
                        <button
                            type="button"
                            onClick={handleLogout}
                            className="w-full py-2 text-slate-500 hover:text-on-surface-variant text-sm font-body transition-all"
                        >
                            Use Different Email
                        </button>
                    </div>
                </form>
            )}

            {status === "verifying" && (
                <div className="bg-surface-container-low border border-outline-variant/10 rounded-2xl p-8">
                    <div className="w-14 h-14 mx-auto mb-5 rounded-2xl bg-primary/10 flex items-center justify-center">
                        <span className="material-symbols-outlined text-primary text-2xl animate-spin">progress_activity</span>
                    </div>
                    <h1 className="text-xl font-headline font-bold text-on-surface mb-2">Verifying Code</h1>
                    <p className="text-on-surface-variant text-sm font-body">Please wait...</p>
                </div>
            )}

            {status === "success" && (
                <div className="bg-surface-container-low border border-outline-variant/10 rounded-2xl p-8">
                    <div className="w-14 h-14 mx-auto mb-5 rounded-2xl bg-emerald-500/10 flex items-center justify-center">
                        <span className="material-symbols-outlined text-emerald-400 text-2xl">check_circle</span>
                    </div>
                    <h1 className="text-xl font-headline font-bold text-on-surface mb-2">Email Verified!</h1>
                    <p className="text-on-surface-variant text-sm mb-6 font-body">Your account is now active. You can start scanning.</p>
                    <Link
                        href="/scan"
                        className="block w-full py-3.5 bg-primary-container hover:bg-[#8433c4] text-on-primary-container font-headline font-bold rounded-xl transition-all text-center active:scale-[0.98]"
                    >
                        Go to Scanner
                    </Link>
                </div>
            )}

            <p className="mt-8 text-slate-600 text-xs font-headline tracking-widest uppercase">
                © 2026 Alif. All rights reserved.
            </p>
        </div>
    );
}

export default function VerifyEmailPage() {
    return (
        <div className="min-h-screen bg-[#12131c] flex items-center justify-center px-4">
            <Suspense fallback={
                <div className="w-full max-w-md text-center">
                    <div className="bg-surface-container-low border border-outline-variant/10 rounded-2xl p-8">
                        <div className="w-14 h-14 mx-auto mb-5 rounded-2xl bg-primary/10 flex items-center justify-center">
                            <span className="material-symbols-outlined text-primary text-2xl animate-spin">progress_activity</span>
                        </div>
                        <p className="text-on-surface-variant text-sm font-body">Loading...</p>
                    </div>
                </div>
            }>
                <VerifyEmailContent />
            </Suspense>
        </div>
    );
}
