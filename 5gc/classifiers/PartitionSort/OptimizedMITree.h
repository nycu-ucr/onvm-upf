#ifndef  OPTMITREE_H
#define  OPTMITREE_H


#include <cstdint>
#include <vector>
#include <set>
#include <algorithm>
#include <cstdio>

#include "red_black_tree.h"
#include "SortableRulesetPartitioner.h"
#include "../ElementaryClasses.h"
#include "../cls_no_virtual.h"

using Memory = std::uint32_t;

class OptimizedMITree final  {

public:
	OptimizedMITree(const SortableRuleset& rules) {
		numRules = 0;
		root = RBTreeCreate();
		// fieldOrder = rules.GetFieldOrdering();
		fieldOrder = CLS_FIELD_ORDER;
		maxPriority = -1;
		for (const auto& r : rules.GetRule()) {
			bool priorityChange;
			Insertion(r, priorityChange);
		}
		
	}
	OptimizedMITree(const FieldOrder& fieldOrder) : fieldOrder(fieldOrder){
		root = RBTreeCreate();
		numRules = 0; 
		maxPriority = -1;
	}
	OptimizedMITree(const Rule& r) {
		root = RBTreeCreate();
		numRules = 0; 
		// fieldOrder = SortableRulesetPartitioner::GetFieldOrderByRule(r);

		/* fieldOrder = {
			13, // IS_UPLINK
			10, // SOURCE_IF
			9,  // TEID
			0,  // UE_IP
			2,  // DST_IP
			1,  // SRC_IP
			11, // NI_HASH
			5,  // PROTO
			4,  // DST_PORT
			3,  // SRC_PORT
			12, // QFI
			6,  // TOS_TC
			7   // SPI
			// (skip 8 FLOW_LABEL since we don’t populate it)
		}; */

		fieldOrder = CLS_FIELD_ORDER;
		maxPriority = -1;
	}
	OptimizedMITree() {
		numRules = 0;
		root = RBTreeCreate();
		fieldOrder = CLS_FIELD_ORDER;
		maxPriority = -1;
	}
	~OptimizedMITree() {
 		  RBTreeDestroy(root);
	}
	void Insertion(const Rule& rule) {
		priorityContainer.insert(rule.priority); 
		maxPriority = std::max(maxPriority, rule.priority);
		RBTreeInsertWithPathCompression(root, rule.range, 0, fieldOrder, rule.priority, rule.descriptor);
		numRules++;
		counter++;
	}
	void Insertion(const Rule& rule, bool& priorityChange) {
	//	if (CanInsertRule(rule)) {
			priorityContainer.insert(rule.priority);
			priorityChange = rule.priority > maxPriority;
			maxPriority = std::max(maxPriority, rule.priority);
			RBTreeInsertWithPathCompression(root, rule.range, 0, fieldOrder, rule.priority, rule.descriptor);
			numRules++; 
			counter++;
   //		} 
	}
	bool TryInsertion(const Rule& rule, bool& priorityChange) {
		if (CanInsertRule(rule)) {
			counter++;
			priorityContainer.insert(rule.priority);
			priorityChange = rule.priority > maxPriority;
			maxPriority = std::max(maxPriority, rule.priority);
			RBTreeInsertWithPathCompression(root, rule.range, 0, fieldOrder, rule.priority, rule.descriptor);
			numRules++;
			return true;
		} else { return false; }
	}

	void Deletion(const Rule& rule, bool& priorityChange) {
	
		auto pit = priorityContainer.equal_range(rule.priority);
	 
		priorityContainer.erase(pit.first);
 
		if (numRules == 1) {
			maxPriority = -1;
			priorityChange = true;
		} else if (rule.priority == maxPriority) {
			priorityChange = true;
			maxPriority = *priorityContainer.rbegin();
		}
		numRules--;
		bool JustDeletedTree;
		RBTreeDeleteWithPathCompression(root, rule.range, 0, fieldOrder, rule.priority, rule.descriptor, JustDeletedTree);
	}
	bool CanInsertRule(const Rule& r) const {
		return RBTreeCanInsert(root, r.range, 0, fieldOrder);
	}
 

	//void DeleteRule(MITreeRule * mrule);
	void  Print() const { RBTreePrint(root); };
	void PrintFieldOrder() const {
		for (size_t i = 0; i < fieldOrder.size(); i++) {
			printf("%d ", fieldOrder[i]);
		}
		printf("\n");
	}
	int ClassifyAPacket(const Packet& one_packet)const {
		return  RBExactQueryIterative(root, one_packet,  fieldOrder);
		//	return   RBExactQuery(root, one_packet, 0,fieldOrder);
	}

	MatchResult ClassifyAPacketMod(const Packet& one_packet)const {
		return  RBExactQueryIterativeMod(root, one_packet,  fieldOrder);
		//	return   RBExactQuery(root, one_packet, 0,fieldOrder);
	}

	/* MatchResult ClassifyAPacketMod(const Packet& one_packet) const {
		printf("=== OptimizedMITree::ClassifyAPacketMod DEBUG ===\n");
		printf("Field order in use: ");
		for(size_t i = 0; i < fieldOrder.size(); i++) {
			printf("%d ", fieldOrder[i]);
		}
		printf("\n");

		MatchResult result = RBExactQueryIterativeMod(root, one_packet, fieldOrder);
		printf("OptimizedMITree result: priority=%d, descriptor=%lu\n", result.priority, result.descriptor);
		return result;
	} */


	int ClassifyAPacket(const Packet& one_packet,int priority_so_far)const {
		return   RBExactQueryPriority(root, one_packet, 0, fieldOrder, priority_so_far);
	}
	//std::vector<MITreeRule *> MRules;

	size_t NumRules() const { return numRules; }
	int MaxPriority() const { return maxPriority; }
	bool Empty() const { return priorityContainer.empty(); }

	void ReconstructIfNumRulesLessThanOrEqualTo(int threshold = 10) {
		if (isMature) return;
		if (numRules >= threshold) {
			isMature = true;  return;
		}
		//global_counter++;
		std::vector<Rule> serialized_rules = SerializeIntoRules();
		auto result = SortableRulesetPartitioner::FastGreedyFieldSelectionForAdaptive(serialized_rules);
		if (!result.first) return;
		if (IsIdenticalVector(fieldOrder, result.second)) return;
		Reset();

		// fieldOrder = result.second;

		fieldOrder = CLS_FIELD_ORDER;

		for (const auto & r : serialized_rules) {
			Insertion(r);
		}
	}
	std::vector<Rule> SerializeIntoRules() const {
		return RBSerializeIntoRules(root, fieldOrder);
	}
	std::vector<Rule> GetRules() const {
		return SerializeIntoRules();
	}

	int MemoryConsumption() const{
		return CalculateMemoryConsumption(root,fieldOrder);
	}

	Memory MemSizeBytes(Memory ruleSize) const {
		return MemoryConsumption();
	}
	
private:
	bool isMature = false;
	rb_red_blk_tree * root;
	int counter = 0;
	int numRules =0;
	FieldOrder fieldOrder;
	std::multiset<int> priorityContainer;
	int maxPriority = -1;
	bool IsIdenticalVector(const FieldOrder& lhs, const std::vector<int>& rhs) {
		if (lhs.size() != rhs.size()) return false;
		for (size_t i = 0; i < lhs.size(); i++) {
			if (lhs[i] != rhs[i]) return false;
		}
		return true;
	};


	void Reset() {

		RBTreeDestroy(root);
		numRules = 0; 
		fieldOrder = CLS_FIELD_ORDER;
		priorityContainer.clear();
		maxPriority = -1;
		root = RBTreeCreate();

	}
	


};


CLS_ENSURE_NO_VIRTUAL(OptimizedMITree);

#endif
