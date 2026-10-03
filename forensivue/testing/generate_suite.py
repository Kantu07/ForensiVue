import os
from forensivue.testing.synthetic_generator import SyntheticImageBuilder

def generate_suite(output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Normal
    print("Generating normal.dd...")
    builder = SyntheticImageBuilder("Hikvision", 5)
    builder.add_recording(1, 1600000000, 1600000060)
    builder.add_recording(1, 1600000060, 1600000120)
    builder.build(os.path.join(output_dir, "normal.dd"))
    
    # 2. Deleted
    print("Generating deleted.dd...")
    builder = SyntheticImageBuilder("Dahua", 5)
    builder.add_recording(1, 1600000000, 1600000060)
    rec2 = builder.add_recording(1, 1600000060, 1600000120)
    builder.mark_deleted(rec2)
    builder.build(os.path.join(output_dir, "deleted.dd"))
    
    # 3. Fragmented
    print("Generating fragmented.dd...")
    builder = SyntheticImageBuilder("Hikvision", 5)
    builder.add_recording(1, 1600000000, 1600000060, fragmented=True)
    builder.build(os.path.join(output_dir, "fragmented.dd"))
    
    # 4. Damaged
    print("Generating damaged.dd...")
    builder = SyntheticImageBuilder("Dahua", 5)
    rec1 = builder.add_recording(1, 1600000000, 1600000060)
    builder.corrupt_block(rec1)
    builder.build(os.path.join(output_dir, "damaged.dd"))
    
    # 5. Multi-channel
    print("Generating multi_channel.dd...")
    builder = SyntheticImageBuilder("Hikvision", 5)
    builder.add_recording(1, 1600000000, 1600000060)
    builder.add_recording(2, 1600000000, 1600000060)
    builder.add_recording(3, 1600000000, 1600000060)
    builder.add_recording(4, 1600000000, 1600000060)
    builder.build(os.path.join(output_dir, "multi_channel.dd"))
    
    # 6. Mixed
    print("Generating mixed.dd...")
    builder = SyntheticImageBuilder("Dahua", 10)
    builder.add_recording(1, 1600000000, 1600000060)
    r2 = builder.add_recording(2, 1600000000, 1600000060, fragmented=True)
    r3 = builder.add_recording(3, 1600000000, 1600000060)
    r4 = builder.add_recording(1, 1600000060, 1600000120)
    builder.corrupt_block(r3)
    builder.mark_deleted(r4)
    builder.build(os.path.join(output_dir, "mixed.dd"))

if __name__ == "__main__":
    generate_suite("generated")
