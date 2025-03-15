#!/usr/bin/env elixir

Mix.install([
  {:httpoison, "~> 1.8"}
])

defmodule SimpleAssetScan do
  @moduledoc """
  SimpleAssetScan - A simplified asset discovery tool.
  """

  # List of common user agents for randomization
  @user_agents [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
  ]

  # List of timeout-related error reasons to ignore
  @timeout_errors [:timeout, :connect_timeout, :recv_timeout]

  @doc """
  Start the scanning process.
  """
  def scan(url, wordlist_path, threads \\ 50, extensions \\ []) do
    url = ensure_trailing_slash(url)

    IO.puts("Starting scan on #{url}")
    IO.puts("Using wordlist: #{wordlist_path}")
    IO.puts("Threads: #{threads}")

    # Load wordlist
    words = load_wordlist(wordlist_path)
    IO.puts("Loaded #{length(words)} words from wordlist")

    # Generate paths to scan
    paths = generate_paths(words, extensions)
    IO.puts("Generated #{length(paths)} paths to scan")
    IO.puts("\nScanning...\n")

    # Start scanning
    start_time = :os.system_time(:millisecond)

    # Create a counter agent
    {:ok, counter} = Agent.start_link(fn -> 0 end)
    total_paths = length(paths)

    results = scan_paths(url, paths, threads, counter, total_paths)

    end_time = :os.system_time(:millisecond)
    duration = (end_time - start_time) / 1000

    # Print summary
    IO.puts("\nScan completed in #{Float.round(duration, 2)} seconds")
    IO.puts("Found #{length(results)} results")

    # Stop the counter agent
    Agent.stop(counter)

    results
  end

  @doc """
  Ensure URL ends with a trailing slash.
  """
  def ensure_trailing_slash(url) do
    if String.ends_with?(url, "/") do
      url
    else
      url <> "/"
    end
  end

  @doc """
  Load wordlist from file.
  """
  def load_wordlist(path) do
    case File.read(path) do
      {:ok, content} ->
        content
        |> String.split("\n")
        |> Enum.map(&String.trim/1)
        |> Enum.filter(fn line ->
          line != "" && !String.starts_with?(line, "#")
        end)

      {:error, reason} ->
        IO.puts("Error loading wordlist: #{inspect(reason)}")
        System.halt(1)
    end
  end

  @doc """
  Generate paths to scan based on wordlist and extensions.
  """
  def generate_paths(words, extensions) do
    if Enum.empty?(extensions) do
      words
    else
      words ++ Enum.flat_map(words, fn word ->
        Enum.map(extensions, fn ext -> "#{word}.#{ext}" end)
      end)
    end
  end

  @doc """
  Get a random user agent from the list.
  """
  def random_user_agent do
    Enum.random(@user_agents)
  end

  @doc """
  Scan paths concurrently.
  """
  def scan_paths(base_url, paths, threads, counter, total) do
    # Use Task.async_stream for controlled concurrency
    paths
    |> Task.async_stream(
      fn path ->
        result = scan_path(base_url, path)

        # Increment counter and print progress
        count = Agent.get_and_update(counter, fn count -> {count + 1, count + 1} end)
        IO.write("\rCompleted: #{count}/#{total}")

        result
      end,
      max_concurrency: threads,
      timeout: 10_000
    )
    |> Enum.reduce([], fn
      {:ok, {:ok, result}}, acc ->
        # Print result in real-time with color
        IO.puts("\n#{IO.ANSI.green()}#{result.status} - #{result.url} (#{result.content_length} bytes)#{IO.ANSI.reset()}")
        [result | acc]
      {:ok, {:error, _reason}}, acc ->
        acc
      {:exit, _reason}, acc ->
        acc
    end)
    |> Enum.reverse()
  end

  @doc """
  Scan a single path.
  """
  def scan_path(base_url, path) do
    url = base_url <> path

    # Prepare request options
    options = [
      timeout: 5000,
      recv_timeout: 5000,
      follow_redirect: true,
      ssl: [verify: :verify_none],
      hackney: [pool: false]  # Prevent connection pooling issues
    ]

    # Prepare headers with random user agent
    headers = %{
      "User-Agent" => random_user_agent()
    }

    # Make the request
    case HTTPoison.get(url, Map.to_list(headers), options) do
      {:ok, %HTTPoison.Response{status_code: status, body: body, headers: resp_headers}} ->
        # Only report successful responses
        if status >= 200 && status < 404 || status == 401 || status == 403 do
          content_length = get_content_length(resp_headers, body)
          content_type = get_content_type(resp_headers)

          {:ok, %{
            url: url,
            path: path,
            status: status,
            content_length: content_length,
            content_type: content_type
          }}
        else
          {:error, "Status code #{status} not interesting"}
        end

      {:error, %HTTPoison.Error{reason: reason}} ->
        # Only log non-timeout errors
        if !is_timeout_error?(reason) do
          IO.puts("\nError connecting to #{url}: #{inspect(reason)}")
        end
        {:error, reason}
    end
  end

  @doc """
  Check if an error is timeout-related.
  """
  def is_timeout_error?(reason) when is_atom(reason) do
    reason in @timeout_errors
  end

  def is_timeout_error?({:closed, _}) do
    true  # Connection closed errors are often related to timeouts
  end

  def is_timeout_error?(_) do
    false
  end

  @doc """
  Get content length from headers or body length.
  """
  def get_content_length(headers, body) do
    headers
    |> Enum.find(fn {key, _} -> String.downcase(key) == "content-length" end)
    |> case do
      {_, value} -> String.to_integer(value)
      nil -> byte_size(body)
    end
  end

  @doc """
  Get content type from headers.
  """
  def get_content_type(headers) do
    headers
    |> Enum.find(fn {key, _} -> String.downcase(key) == "content-type" end)
    |> case do
      {_, value} -> value
      nil -> "unknown"
    end
  end
end

defmodule SimpleAssetScan.CLI do
  @doc """
  Parse command-line arguments and run SimpleAssetScan.
  """
  def main(args) do
    # Print banner
    print_banner()

    {opts, args, _} = OptionParser.parse(args,
      switches: [
        wordlist: :string,
        extensions: :string,
        threads: :integer,
        help: :boolean
      ],
      aliases: [
        w: :wordlist,
        e: :extensions,
        t: :threads,
        h: :help
      ]
    )

    if opts[:help] || length(args) == 0 do
      print_help()
      System.halt(0)
    end

    url = List.first(args)

    # Process options
    wordlist = opts[:wordlist] || "wordlist.txt"

    extensions = if opts[:extensions] do
      String.split(opts[:extensions], ",")
    else
      []
    end

    threads = opts[:threads] || 50

    # Run scan
    SimpleAssetScan.scan(url, wordlist, threads, extensions)
  end

  @doc """
  Print the SimpleAssetScan banner.
  """
  def print_banner do
    banner = """
    ┌─────────────────────────────────────────────────┐
    │ AssetScan - Asset Discovery Tool                │
    └─────────────────────────────────────────────────┘
    """

    IO.puts(banner)
  end

  @doc """
  Print the help message.
  """
  def print_help do
    help = """
    Usage: simple_asset_scan [options] <url>

    Options:
      -w, --wordlist PATH       Path to wordlist file (default: wordlist.txt)
      -e, --extensions LIST     Comma-separated list of extensions to check
      -t, --threads NUM         Number of concurrent threads (default: 50)
      -h, --help                Show this help message

    Examples:
      simple_asset_scan https://example.com
      simple_asset_scan -w paths.txt -e php,html,js https://example.com
    """

    IO.puts(help)
  end
end

# Run the CLI if script is executed directly
SimpleAssetScan.CLI.main(System.argv())
