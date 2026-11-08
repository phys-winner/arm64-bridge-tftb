// SHA verifier is copied from the current FPS verifier with only its
// own name, exact SDL size and expected digest changed. FPS stays intact.
bool VerifyTftbSdlImage(JNIEnv* env, const uint8_t* image, size_t size) {
    static constexpr std::array<unsigned char, 32> expected = {
        0xa6,0xbc,0x07,0x6a,0x11,0x14,0x2c,0xe8,0xe3,0x18,0xbc,0x23,0x59,0x74,0x90,0xfe,
        0x07,0x1a,0x25,0xe3,0x7c,0xdb,0xa6,0x29,0xd5,0x2a,0x53,0xa1,0x92,0x92,0x3b,0xfb};
    if (!env || env->ExceptionCheck() || !image || size != 832984 || env->PushLocalFrame(8) < 0)
        return false;
    struct Frame { JNIEnv* env; ~Frame() { env->PopLocalFrame(nullptr); } } frame{env};
    jclass cls = env->FindClass("java/security/MessageDigest");
    if (!cls || env->ExceptionCheck()) return false;
    jmethodID factory = env->GetStaticMethodID(cls, "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    if (!factory || env->ExceptionCheck()) return false;
    jmethodID update = env->GetMethodID(cls, "update", "(Ljava/nio/ByteBuffer;)V");
    if (!update || env->ExceptionCheck()) return false;
    jmethodID digest = env->GetMethodID(cls, "digest", "()[B");
    if (!digest || env->ExceptionCheck()) return false;
    jstring algorithm = env->NewStringUTF("SHA-256");
    if (!algorithm || env->ExceptionCheck()) return false;
    jobject context = env->CallStaticObjectMethod(cls, factory, algorithm);
    if (!context || env->ExceptionCheck()) return false;
    jobject bytes = env->NewDirectByteBuffer(const_cast<uint8_t*>(image), static_cast<jlong>(size));
    if (!bytes || env->ExceptionCheck()) return false;
    env->CallVoidMethod(context, update, bytes);
    if (env->ExceptionCheck()) return false;
    auto result = static_cast<jbyteArray>(env->CallObjectMethod(context, digest));
    if (!result || env->ExceptionCheck() || env->GetArrayLength(result) != 32) return false;
    std::array<jbyte, 32> actual{};
    env->GetByteArrayRegion(result, 0, 32, actual.data());
    return !env->ExceptionCheck() && !std::memcmp(actual.data(), expected.data(), expected.size());
}

// Keep the original SDL image intact; install after the load-group audit,
// before initializers. All validation precedes the sole two-byte write.
static bool InstallTftbPrimaryTouchMotion(DynarmicHost& runtime, bool image_verified) {
    const ElfLoader* sdl = runtime.FindModule("libSDL2.so");
    const ElfSymbol* touch = sdl ? sdl->GetExportedSymbol("Android_OnTouch") : nullptr;
    constexpr uint32_t rva = 0x00089A98u;
    constexpr uint32_t gate_offset = 0x132u;
    constexpr std::array<uint16_t, 242> original = {
        0xE92Du, 0x43F0u, 0xAF03u, 0xB081u, 0xED2Du, 0x8B06u, 0xB088u, 0x4605u,
        0x4868u, 0x4689u, 0x4968u, 0x4478u, 0x461Cu, 0x4479u, 0x4616u, 0x6800u,
        0x6809u, 0x6800u, 0x9007u, 0x6808u, 0x2800u, 0xF000u, 0x80B3u, 0x4A63u,
        0xEA4Fu, 0x78E5u, 0x4628u, 0x4641u, 0x447Au, 0xF790u, 0xEF54u, 0xF1B0u,
        0x3FFFu, 0xDC06u, 0x485Eu, 0x2250u, 0x495Eu, 0x4478u, 0x4479u, 0xF790u,
        0xE81Eu, 0x2E06u, 0xF200u, 0x809Eu, 0xED97u, 0x8A05u, 0xED97u, 0x9A04u,
        0xEE0Au, 0x4A10u, 0xE8DFu, 0xF006u, 0x4304u, 0x9661u, 0x3396u, 0x004Fu,
        0x4859u, 0xA906u, 0xAA05u, 0x4478u, 0x6800u, 0x6800u, 0xF78Fu, 0xED54u,
        0xED9Du, 0x0A05u, 0x2000u, 0xF04Fu, 0x31FFu, 0x2200u, 0xEEB8u, 0x0AC0u,
        0xED9Du, 0x1A06u, 0xEEB8u, 0x1AC1u, 0xEE20u, 0x0A09u, 0xEE21u, 0x1A0Au,
        0xEEBDu, 0x0AC0u, 0xEEBDu, 0x1AC1u, 0xED8Du, 0x0A00u, 0xEE11u, 0x3A10u,
        0xF78Fu, 0xED6Au, 0x2000u, 0xF04Fu, 0x31FFu, 0x2201u, 0x2301u, 0xF78Fu,
        0xED28u, 0x4846u, 0xEA4Fu, 0x71E9u, 0x4478u, 0xE9C0u, 0x9100u, 0x2001u,
        0xED8Du, 0xAA01u, 0xED8Du, 0x9A02u, 0xEA4Fu, 0x73E9u, 0xED8Du, 0x8A03u,
        0x4641u, 0x9000u, 0x4628u, 0x464Au, 0xF78Fu, 0xED84u, 0xE052u, 0x4836u,
        0x2100u, 0x2200u, 0x2301u, 0x4478u, 0xE9C0u, 0x1100u, 0x2000u, 0xF04Fu,
        0x31FFu, 0xF78Fu, 0xED06u, 0x2000u, 0xED8Du, 0xAA01u, 0xED8Du, 0x9A02u,
        0xEA4Fu, 0x73E9u, 0xED8Du, 0x8A03u, 0x4641u, 0x9000u, 0x4628u, 0x464Au,
        0xF78Fu, 0xED68u, 0x4829u, 0x4478u, 0xE036u, 0x4829u, 0x4478u, 0xE9D0u,
        0x0100u, 0x4308u, 0xD121u, 0x4827u, 0xA906u, 0xAA05u, 0x4478u, 0x6800u,
        0x6800u, 0xF78Fu, 0xECF2u, 0xED9Du, 0x0A05u, 0x2000u, 0xF04Fu, 0x31FFu,
        0x2200u, 0xEEB8u, 0x0AC0u, 0xED9Du, 0x1A06u, 0xEEB8u, 0x1AC1u, 0xEE20u,
        0x0A09u, 0xEE21u, 0x1A0Au, 0xEEBDu, 0x0AC0u, 0xEEBDu, 0x1AC1u, 0xED8Du,
        0x0A00u, 0xEE11u, 0x3A10u, 0xF78Fu, 0xED08u, 0xEA4Fu, 0x73E9u, 0x4628u,
        0x4641u, 0x464Au, 0xED8Du, 0xAA00u, 0xED8Du, 0x9A01u, 0xED8Du, 0x8A02u,
        0xF790u, 0xEEAEu, 0x4812u, 0x4478u, 0x6800u, 0x9907u, 0x6800u, 0x1A40u,
        0xBF01u, 0xB008u, 0xECBDu, 0x8B06u, 0xB001u, 0xE8BDu, 0x83F0u, 0xF78Fu,
        0xEA22u, 0xBF00u, 0xEEF6u, 0x0003u, 0xEF06u, 0x0003u, 0xD027u, 0x0000u,
        0x11E8u, 0x0001u, 0x1204u, 0x0001u, 0x40C6u, 0x0004u, 0xEDE6u, 0x0003u,
        0x4090u, 0x0004u, 0xEDE4u, 0x0003u, 0xEEAAu, 0x0003u, 0x40F4u, 0x0004u,
        0xED76u, 0x0003u,
    };
    auto refuse = []() {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
            "TFTB primary touch motion refused: exact SDL fingerprint mismatch; no writes.");
        return false;
    };
    if (!image_verified || !touch || touch->type != STT_FUNC || touch->size != sizeof(original) ||
        static_cast<uint64_t>(touch->value) !=
            static_cast<uint64_t>(sdl->GetBaseAddress()) + rva + 1u)
        return refuse();
    const uint32_t start = touch->value & ~1u;
    const uint64_t end = static_cast<uint64_t>(start) + sizeof(original);
    if (end > runtime.GetGuestMemorySize()) return refuse();
    bool executable = false;
    for (const ElfSegment& segment : sdl->GetSegments()) {
        const uint64_t lower = static_cast<uint64_t>(sdl->GetBaseAddress()) + segment.vaddr;
        if (segment.flags == (PF_R | PF_X) && start >= lower && end <= lower + segment.filesz)
            executable = true;
    }
    if (!executable) return refuse();
    for (size_t i = 0; i < original.size(); ++i)
        if (runtime.MemoryRead16(start + static_cast<uint32_t>(i * 2)) != original[i])
            return refuse();
    // r0: cached primary finger low32; r9: current Android nonnegative pointer ID.
    // Keep the original BNE and both original mouse/finger event paths.
    runtime.MemoryWrite16(start + gate_offset, 0x4548u); // cmp r0,r9 (was orrs r0,r1)
    runtime.InvalidateGuestCode(start + gate_offset, sizeof(uint16_t));
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
        "TFTB primary touch motion applied: gate=0x%08X", start + gate_offset);
    return true;
}
