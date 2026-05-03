use std::borrow::Cow;
use std::time::Instant;

pub mod pbkdf2;
pub mod sha1;

pub struct AdapterSummary {
    pub name: String,
    pub backend: String,
    pub device_type: String,
    pub driver: String,
    pub driver_info: String,
}

pub fn list_adapters() -> Vec<AdapterSummary> {
    pollster::block_on(list_adapters_async())
}

async fn list_adapters_async() -> Vec<AdapterSummary> {
    let instance = wgpu::Instance::default();
    instance
        .enumerate_adapters(wgpu::Backends::all())
        .await
        .into_iter()
        .map(|adapter| {
            let info = adapter.get_info();
            AdapterSummary {
                name: info.name,
                backend: format!("{:?}", info.backend),
                device_type: format!("{:?}", info.device_type),
                driver: info.driver,
                driver_info: info.driver_info,
            }
        })
        .collect()
}

pub struct GpuContext {
    pub device: wgpu::Device,
    pub queue: wgpu::Queue,
    pub adapter_name: String,
    pub backend: String,
    pub device_type: String,
    pub driver: String,
}

impl GpuContext {
    pub fn init_blocking() -> Result<Self, String> {
        pollster::block_on(Self::init())
    }

    pub async fn init() -> Result<Self, String> {
        let instance = wgpu::Instance::default();
        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                force_fallback_adapter: false,
                compatible_surface: None,
            })
            .await
            .map_err(|e| format!("no compatible GPU adapter found: {e}"))?;

        let info = adapter.get_info();
        let adapter_name = info.name.clone();
        let backend = format!("{:?}", info.backend);
        let device_type = format!("{:?}", info.device_type);
        let driver = format!("{} ({})", info.driver, info.driver_info);

        let (device, queue) = adapter
            .request_device(&wgpu::DeviceDescriptor {
                label: Some("zip-password-finder"),
                required_features: wgpu::Features::empty(),
                required_limits: wgpu::Limits::downlevel_defaults(),
                memory_hints: wgpu::MemoryHints::Performance,
                experimental_features: wgpu::ExperimentalFeatures::disabled(),
                trace: wgpu::Trace::Off,
            })
            .await
            .map_err(|e| format!("request_device failed: {e}"))?;

        Ok(Self {
            device,
            queue,
            adapter_name,
            backend,
            device_type,
            driver,
        })
    }
}

pub struct SmokeTestReport {
    pub adapter_name: String,
    pub backend: String,
    pub device_type: String,
    pub driver: String,
    pub elements_processed: usize,
    pub elapsed_ms: f64,
}

pub fn smoke_test() -> Result<SmokeTestReport, String> {
    let ctx = GpuContext::init_blocking()?;
    pollster::block_on(smoke_test_async(&ctx))
}

async fn smoke_test_async(ctx: &GpuContext) -> Result<SmokeTestReport, String> {
    use wgpu::util::DeviceExt;

    const N: usize = 1024 * 16;
    let input: Vec<u32> = (0..N as u32).collect();
    let bytes: &[u8] = bytemuck::cast_slice(&input);

    let storage = ctx
        .device
        .create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("smoke-test-storage"),
            contents: bytes,
            usage: wgpu::BufferUsages::STORAGE
                | wgpu::BufferUsages::COPY_DST
                | wgpu::BufferUsages::COPY_SRC,
        });

    let staging = ctx.device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("smoke-test-staging"),
        size: bytes.len() as u64,
        usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    let shader = ctx
        .device
        .create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("smoke-test-shader"),
            source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(include_str!("smoke_test.wgsl"))),
        });

    let pipeline = ctx
        .device
        .create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("smoke-test-pipeline"),
            layout: None,
            module: &shader,
            entry_point: Some("main"),
            compilation_options: Default::default(),
            cache: None,
        });

    let bind_group_layout = pipeline.get_bind_group_layout(0);
    let bind_group = ctx.device.create_bind_group(&wgpu::BindGroupDescriptor {
        label: Some("smoke-test-bind-group"),
        layout: &bind_group_layout,
        entries: &[wgpu::BindGroupEntry {
            binding: 0,
            resource: storage.as_entire_binding(),
        }],
    });

    let start = Instant::now();
    let mut encoder = ctx
        .device
        .create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("smoke-test-encoder"),
        });
    {
        let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
            label: Some("smoke-test-pass"),
            timestamp_writes: None,
        });
        pass.set_pipeline(&pipeline);
        pass.set_bind_group(0, &bind_group, &[]);
        let workgroups = N.div_ceil(64) as u32;
        pass.dispatch_workgroups(workgroups, 1, 1);
    }
    encoder.copy_buffer_to_buffer(&storage, 0, &staging, 0, bytes.len() as u64);
    ctx.queue.submit(Some(encoder.finish()));

    let buffer_slice = staging.slice(..);
    let (sender, receiver) = std::sync::mpsc::channel();
    buffer_slice.map_async(wgpu::MapMode::Read, move |result| {
        let _ = sender.send(result);
    });

    ctx.device
        .poll(wgpu::PollType::wait_indefinitely())
        .expect("poll");

    receiver
        .recv()
        .map_err(|e| format!("map_async channel closed: {e}"))?
        .map_err(|e| format!("buffer map failed: {e}"))?;

    let mapped = buffer_slice.get_mapped_range();
    let result: &[u32] = bytemuck::cast_slice(&mapped);
    for (i, &v) in result.iter().enumerate() {
        let expected = i as u32 + 1;
        if v != expected {
            return Err(format!(
                "kernel produced wrong result at index {i}: expected {expected}, got {v}"
            ));
        }
    }

    let elapsed = start.elapsed();
    drop(mapped);
    staging.unmap();

    Ok(SmokeTestReport {
        adapter_name: ctx.adapter_name.clone(),
        backend: ctx.backend.clone(),
        device_type: ctx.device_type.clone(),
        driver: ctx.driver.clone(),
        elements_processed: N,
        elapsed_ms: elapsed.as_secs_f64() * 1000.0,
    })
}

pub fn run_smoke_test_cli() -> i32 {
    println!("Available adapters:");
    let adapters = list_adapters();
    if adapters.is_empty() {
        println!("  (none)");
    } else {
        for (i, a) in adapters.iter().enumerate() {
            println!(
                "  [{i}] {} | backend={} | type={} | driver={} ({})",
                a.name, a.backend, a.device_type, a.driver, a.driver_info
            );
        }
    }
    println!();
    println!("Running smoke test on highest-performance adapter...");
    match smoke_test() {
        Ok(report) => {
            println!("OK");
            println!("  adapter:   {}", report.adapter_name);
            println!("  backend:   {}", report.backend);
            println!("  type:      {}", report.device_type);
            println!("  driver:    {}", report.driver);
            println!("  elements:  {}", report.elements_processed);
            println!("  dispatch:  {:.3} ms", report.elapsed_ms);
            0
        }
        Err(e) => {
            eprintln!("FAIL: {e}");
            1
        }
    }
}
