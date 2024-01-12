#pragma once

#include <list>

#include "logger.h"
#define LOG_LEVEL LL_INFO
#include "logger.h"

constexpr auto INDEX_OUT_OF_BOUNDS = -2;

class Segment {
	public:
		int address;
		int size;

		Segment(int address, int size) {
			this->address = address;
			this->size = size;
		}

		int getEnd() {
			return address + size;
		}
};

class MemoryManager {
	private:
		std::list<Segment> freeSegments;

	public:
		bool addFreeSpace(const int address, const int size) {
			if (size <= 0) {
				TRACE("not adding zero length segment at %i", address);
				return false;
			}
			for (auto pos = freeSegments.begin(); pos != freeSegments.end(); ++pos) {
				Segment& segment = *pos;
				if (segment.address >= address) {
					if (address + size < segment.address) {
						TRACE("adding segment %i -> %i", address, address + size);
						freeSegments.insert(pos, Segment(address, size));	//Insert new segment before current segment
					} else if (address + size == segment.address) {
						TRACE("extending segment %i -> %i backward to %i -> %i", segment.address, segment.address + segment.size,
								address, segment.address + segment.size);
						segment.address = address;			//New segment ends at current segment, extend backward
						segment.size += size;
					} else {
						ERR("segment %i -> %i overlaps with %i -> %i\n", address, address + size,
								segment.address, segment.address + segment.size);
						return false;						//New segment overlaps next segment, fail
					}
					return true;
				} else if (segment.address + segment.size == address) {
					TRACE("extending segment %i -> %i to %i -> %i", segment.address, segment.address + segment.size,
							segment.address, segment.address + segment.size + size);
					segment.size += size;					//Current segment ends at new segment, extend forward
					return true;
				} else if (segment.address + segment.size > address) {
					ERR("segment %i -> %i overlaps with %i -> %i", address, address + size,
							segment.address, segment.address + segment.size);
					return false;							//Current segment overlaps new segment, fail
				}
			}
			TRACE("adding segment %i -> %i", address, address + size);
			freeSegments.push_back(Segment(address, size));	//Insert new segment after last segment
			return true;
		}

		int getFreeSpace(const int size) {
			for (auto pos = freeSegments.begin(); pos != freeSegments.end(); ++pos) {
				Segment& segment = *pos;
				if (segment.size == size) {
					const int address = segment.address;
					freeSegments.erase(pos);
					return address;
				} else if (segment.size > size) {
					const int address = segment.address;
					segment.address += size;		//Shift the free segment forward...
					segment.size -= size;			//... and shrink it
					return address;
				}
			}
			return -1;
		}

		int setTotalSize(int size) {
			if (!freeSegments.empty() && freeSegments.back().getEnd() >= size) {
				for (auto pos = freeSegments.begin(); pos != freeSegments.end(); ++pos) {
					Segment segment = *pos;
					if (segment.address + segment.size >= size) {
						size = segment.address;							//Size can be reduced to the beginning of this segment
						freeSegments.erase(pos, freeSegments.end());	//Delete all free segments past new size
						break;
					}
				}
			}
			return size;
		}

		void printSegments() {
			for (Segment segment : freeSegments) {
				printf("segment %5i -> %5i\n", segment.address, segment.address + segment.size);
			}
		}
};
