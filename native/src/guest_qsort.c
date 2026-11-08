typedef unsigned int guest_qsort_u32;
typedef unsigned char guest_qsort_byte;
typedef int (*guest_qsort_compare)(const void*, const void*);

static guest_qsort_byte* guest_qsort_record(guest_qsort_byte* base,
                                             guest_qsort_u32 index,
                                             guest_qsort_u32 width) {
    return base + index * width;
}

static void guest_qsort_swap(guest_qsort_byte* left, guest_qsort_byte* right,
                              guest_qsort_u32 width) {
    guest_qsort_u32 i = 0;
    while (i < width) {
        const guest_qsort_byte value = left[i];
        left[i] = right[i];
        right[i] = value;
        ++i;
    }
}

static void guest_qsort_sift_down(guest_qsort_byte* base,
                                  guest_qsort_u32 root,
                                  guest_qsort_u32 count,
                                  guest_qsort_u32 width,
                                  guest_qsort_compare compare) {
    if (root >= count || count < 2u || root > ((count - 2u) >> 1)) return;

    for (;;) {
        const guest_qsort_u32 child = (root << 1) + 1u;
        if (child >= count) return;

        guest_qsort_u32 selected = child;
        if (child + 1u < count &&
            compare(guest_qsort_record(base, child, width),
                    guest_qsort_record(base, child + 1u, width)) < 0) {
            selected = child + 1u;
        }

        if (compare(guest_qsort_record(base, root, width),
                    guest_qsort_record(base, selected, width)) >= 0) return;

        guest_qsort_swap(guest_qsort_record(base, root, width),
                         guest_qsort_record(base, selected, width), width);
        root = selected;
        if (root >= count || root > ((count - 2u) >> 1)) return;
    }
}

__attribute__((section(".text.guest_qsort_entry"), used))
void guest_qsort_entry(void* base, guest_qsort_u32 count,
                       guest_qsort_u32 width, guest_qsort_compare compare) {
    if (!base || !count || !width || !compare || count < 2u) return;

    guest_qsort_u32 start = count >> 1;
    while (start != 0) {
        --start;
        guest_qsort_sift_down((guest_qsort_byte*)base, start, count, width, compare);
    }

    guest_qsort_u32 end = count;
    while (end > 1u) {
        --end;
        guest_qsort_swap(guest_qsort_record((guest_qsort_byte*)base, 0, width),
                         guest_qsort_record((guest_qsort_byte*)base, end, width), width);
        guest_qsort_sift_down((guest_qsort_byte*)base, 0, end, width, compare);
    }
}
